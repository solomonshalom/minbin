/**
 * src/app.ts
 *
 * Builds the Fastify application with all routes wired up. The Redis client is
 * injected so tests can pass an in-memory mock without touching the network.
 */

import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import Fastify, {
    type FastifyError,
    type FastifyInstance,
    type FastifyReply,
    type FastifyRequest,
} from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifySwagger from '@fastify/swagger';
import nunjucks from 'nunjucks';
import type { Redis } from 'ioredis';

import { Config } from './config.js';
import { getVersion } from './version.js';

// Resolve templates relative to this file so the app works whether it runs
// from `dist/`, from source via tsx, or bundled into a serverless function.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function resolveTemplatesDir(): string {
    const candidates = [
        resolve(__dirname, '..', 'templates'),
        resolve(process.cwd(), 'templates'),
    ];
    for (const candidate of candidates) {
        if (existsSync(candidate)) return candidate;
    }
    return candidates[0];
}

const TEMPLATES_DIR = resolveTemplatesDir();
const ASSETS_DIR = resolve(TEMPLATES_DIR, 'assets');

const HTML_CONTENT_TYPE = 'text/html; charset=utf-8';
const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

type PasteRecord = {
    body?: unknown;
    once?: unknown;
};

export interface AppOptions {
    redis: Redis;
    logger?: boolean | object;
}

export async function createApp(opts: AppOptions): Promise<FastifyInstance> {
    const { redis } = opts;

    const njEnv = nunjucks.configure(TEMPLATES_DIR, {
        autoescape: true,
        noCache: process.env.NODE_ENV !== 'production',
        throwOnUndefined: false,
    });

    const renderTemplate = (
        name: string,
        ctx: Record<string, unknown> = {},
    ): string => njEnv.render(name, ctx);

    const fastify = Fastify({
        logger:
            opts.logger === undefined
                ? { level: process.env.LOG_LEVEL ?? 'info' }
                : opts.logger,
        bodyLimit: Config.MAX_PASTE_SIZE,
        trustProxy: true,
        disableRequestLogging: false,
    });

    redis.on('error', (err: Error) => {
        fastify.log.error({ err }, 'redis client error');
    });
    redis.on('connect', () => {
        fastify.log.info(
            { host: Config.DB_HOST, port: Config.DB_PORT },
            'redis connected',
        );
    });
    redis.on('reconnecting', () => {
        fastify.log.warn('redis reconnecting');
    });

    await fastify.register(fastifySwagger, {
        openapi: {
            info: {
                title: 'minbin',
                description: 'a minimal, ephemeral pastebin service',
                version: getVersion(),
            },
        },
    });

    await fastify.register(fastifyStatic, {
        root: ASSETS_DIR,
        prefix: '/assets/',
        decorateReply: false,
        wildcard: true,
        index: false,
        list: false,
    });

    // match python's `await request.body()` -- read any content type as raw bytes.
    fastify.removeAllContentTypeParsers();
    fastify.addContentTypeParser(
        '*',
        { parseAs: 'buffer' },
        (_req, body, done) => {
            done(null, body);
        },
    );

    fastify.setErrorHandler((
        error: FastifyError,
        request: FastifyRequest,
        reply: FastifyReply,
    ) => {
        // body too large -> match python's 400 + plain-text message
        if (
            error.code === 'FST_ERR_CTP_BODY_TOO_LARGE' ||
            error.statusCode === 413
        ) {
            return reply
                .code(400)
                .type(TEXT_CONTENT_TYPE)
                .send('Paste body is empty or exceeds maximum size.');
        }

        // schema validation errors -> 422 detail (FastAPI shape)
        if (error.validation) {
            return reply
                .code(error.statusCode ?? 422)
                .type(JSON_CONTENT_TYPE)
                .send({ detail: error.message });
        }

        request.log.error({ err: error }, 'unhandled error');
        const status = error.statusCode && error.statusCode >= 400 ? error.statusCode : 500;
        return reply
            .code(status)
            .type(JSON_CONTENT_TYPE)
            .send({
                detail:
                    status >= 500
                        ? 'Internal Server Error'
                        : (error.message ?? 'Error'),
            });
    });

    fastify.setNotFoundHandler((_request, reply) => {
        return reply
            .code(404)
            .type(JSON_CONTENT_TYPE)
            .send({ detail: 'Not Found' });
    });

    // expose the openapi document at /openapi (matches the python implementation)
    fastify.get(
        '/openapi',
        { schema: { hide: true } },
        async (_request, reply) => {
            return reply.type(JSON_CONTENT_TYPE).send(fastify.swagger());
        },
    );

    fastify.get(
        '/',
        {
            schema: {
                summary: 'Get the index page.',
                description: 'Get the index page.',
                response: {
                    200: { type: 'string', description: 'HTML page' },
                },
            },
        },
        async (_request, reply) => {
            const html = renderTemplate('index.html');
            return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
        },
    );

    fastify.post<{
        Querystring: { once?: string; relative?: boolean };
    }>(
        '/',
        {
            schema: {
                summary: 'Create a new paste.',
                description: 'Create a new paste.',
                querystring: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                        once: {
                            type: 'string',
                            description:
                                'If true, the paste will self-destruct after one view.',
                        },
                        relative: {
                            type: 'boolean',
                            description:
                                'If true, only return the paste ID instead of the full URL.',
                            default: false,
                        },
                    },
                },
                response: {
                    201: { type: 'string', description: 'Paste URL or ID' },
                    400: { type: 'string', description: 'Bad request' },
                },
            },
        },
        async (request, reply) => {
            const body = request.body as Buffer | undefined | null;

            if (
                !body ||
                body.length === 0 ||
                body.length > Config.MAX_PASTE_SIZE
            ) {
                return reply
                    .code(400)
                    .type(TEXT_CONTENT_TYPE)
                    .send('Paste body is empty or exceeds maximum size.');
            }

            const pasteId = randomBytes(2).toString('hex');
            const pasteExpirySeconds = Config.PASTE_EXPIRY * 60;
            // matches python: bool(once is not None) -- presence of the param turns it on.
            const onceFlag = request.query.once !== undefined;
            const relative = request.query.relative === true;

            const pasteContent = JSON.stringify({
                body: body.toString('utf8'),
                once: onceFlag,
            });

            await redis.set(pasteId, pasteContent, 'EX', pasteExpirySeconds);

            reply.code(201).type(TEXT_CONTENT_TYPE);
            if (relative) {
                return pasteId;
            }
            return `${Config.APP_DOMAIN}/${pasteId}`;
        },
    );

    fastify.get<{ Params: { paste_id: string } }>(
        '/raw/:paste_id',
        {
            schema: {
                summary: 'Get the raw paste content by ID.',
                description: 'Get the raw paste content by ID.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
                response: {
                    200: { type: 'string', description: 'Raw paste body' },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            const pasteContent = await redis.get(paste_id);

            if (pasteContent === null) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({
                        detail: `Paste with ID '${paste_id}' not found.`,
                    });
            }

            let parsed: PasteRecord;
            try {
                parsed = JSON.parse(pasteContent) as PasteRecord;
            } catch (err) {
                request.log.error(
                    { err, paste_id },
                    'failed to parse paste content from redis',
                );
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            const pasteBody =
                typeof parsed.body === 'string' ? parsed.body : '';

            if (parsed.once === true) {
                await redis.del(paste_id);
            }

            return reply
                .code(200)
                .type(TEXT_CONTENT_TYPE)
                .send(pasteBody);
        },
    );

    fastify.get<{ Params: { paste_id: string } }>(
        '/:paste_id',
        {
            schema: {
                summary: 'Get the paste content by ID.',
                description: 'Get the paste content by ID.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
                response: {
                    200: {
                        type: 'string',
                        description: 'HTML page with paste content',
                    },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;

            const [pasteContent, pasteTtl] = await Promise.all([
                redis.get(paste_id),
                redis.ttl(paste_id),
            ]);

            if (pasteContent === null) {
                const html = renderTemplate('404.html');
                return reply
                    .code(404)
                    .type(HTML_CONTENT_TYPE)
                    .send(html);
            }

            let parsed: PasteRecord;
            try {
                parsed = JSON.parse(pasteContent) as PasteRecord;
            } catch (err) {
                request.log.error(
                    { err, paste_id },
                    'failed to parse paste content from redis',
                );
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            const pasteBody =
                typeof parsed.body === 'string' ? parsed.body : '';

            if (parsed.once === true) {
                await redis.del(paste_id);
            }

            const html = renderTemplate('paste.html', {
                paste_id,
                paste_body: pasteBody,
                paste_expiry: pasteTtl,
                app_domain: Config.APP_DOMAIN,
            });

            return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
        },
    );

    return fastify;
}
