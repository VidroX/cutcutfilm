import express from 'express';
import http from 'http';
import path from 'path';
import { readFileSync } from 'fs';
import { ApolloGateway, RemoteGraphQLDataSource } from '@apollo/gateway';
import { ApolloServer } from '@apollo/server';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import { expressMiddleware } from '@apollo/server/express4';
import bodyParser from 'body-parser';
import cors from 'cors';
import {
	ApolloServerPluginInlineTraceDisabled,
	ApolloServerPluginLandingPageDisabled,
	ApolloServerPluginUsageReportingDisabled,
} from '@apollo/server/plugin/disabled';
import { ApolloServerPluginInlineTrace } from '@apollo/server/plugin/inlineTrace';
import responseCachePlugin from '@apollo/server-plugin-response-cache';
import { rootDir } from './path_utils.js';
import {
	DEBUG,
	IDENTITY_SERVICE_API_KEY,
	IDENTITY_SERVICE_LOCATION,
	NODE_ENV,
	PORT,
} from './environment.js';
import { createPromiseClient } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-node';
import { IdentityService } from './proto/identity/v1/identity_connect.js';
import CookiePassthroughPlugin, {
	parseServiceCookieString,
} from './plugins/cookie-passthrough-plugin.js';
import cookie from 'cookie';
import { rateLimit } from 'express-rate-limit';

const app = express();
const httpServer = http.createServer(app);

const supergraphPath = path.join(rootDir, '..', 'supergraph.graphql');

const identityServiceConnector = createConnectTransport({
	baseUrl: IDENTITY_SERVICE_LOCATION,
	httpVersion: '2',
});
const identityServiceClient = createPromiseClient(IdentityService, identityServiceConnector);

let keySet: any = '';

try {
	const identityKeySet = await identityServiceClient.getKeySet(
		{},
		{ headers: { 'x-api-key': IDENTITY_SERVICE_API_KEY } }
	);

	keySet = JSON.parse(Buffer.from(identityKeySet.encodedKeys, 'base64').toString('utf8'));
} catch (err: any) {
	if (DEBUG) {
		console.log('Unable to get keyset from Identity Service:', err);
	}

	throw err;
}

app.get('/certs', (req, res) => {
	res.send(keySet);
});

const gateway = new ApolloGateway({
	debug: DEBUG,
	supergraphSdl: readFileSync(supergraphPath).toString(),
	buildService({ url }) {
		return new RemoteGraphQLDataSource({
			url,
			didReceiveResponse({ response, context }) {
				const cookies = response.http?.headers?.get('set-cookie') as string | null;

				if (cookies != null) {
					context['cookies'] = parseServiceCookieString(cookies);
				}

				return response;
			},
			willSendRequest({ request, context }) {
				if (context.acceptLanguage != null) {
					request.http?.headers.set('Accept-Language', context.acceptLanguage);
				}

				if (context?.token != null) {
					request.http?.headers.set('Authorization', context.token);
				}
			},
		});
	},
});

const debugPlugins = DEBUG
	? [
			ApolloServerPluginInlineTrace({
				includeErrors: { transform: (err) => err },
			}),
	  ]
	: [
			ApolloServerPluginUsageReportingDisabled(),
			ApolloServerPluginInlineTraceDisabled(),
			ApolloServerPluginLandingPageDisabled(),
	  ];

const server = new ApolloServer({
	gateway,
	nodeEnv: NODE_ENV,
	includeStacktraceInErrorResponses: DEBUG,
	introspection: DEBUG,
	plugins: [
		...debugPlugins,
		responseCachePlugin(),
		ApolloServerPluginDrainHttpServer({ httpServer }),
		CookiePassthroughPlugin(),
	],
});

await server.start();

const allowedOrigins = [
	`http://localhost:${PORT}`,
	`http://localhost:3000`,
	'http://localhost',
	'https://ccf-dev.vidrox.me',
	'https://cutcutfilm.com',
];

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 100,
	standardHeaders: true,
	legacyHeaders: false,
});

app.use(limiter);

app.use(
	'/gql',
	cors({
		origin: function (origin, callback) {
			if (!origin) {
				return callback(null, true);
			}

			if (allowedOrigins.indexOf(origin) === -1) {
				const msg = 'The CORS policy does not allow access from the specified Origin.';

				return callback(new Error(msg), false);
			}

			return callback(null, true);
		},
		credentials: true,
	}),
	bodyParser.json({ limit: '10mb' }),
	expressMiddleware(server, {
		context: async ({ req }) => {
			const cookies = cookie.parse(req.headers.cookie ?? '');

			const headerToken = (req.headers?.authorization ?? '').trim().replace('Bearer ', '');
			const accessToken = cookies?.at?.trim() ?? '';
			const refreshToken = cookies?.rt?.trim() ?? '';

			const acceptLanguage = req.headers['accept-language'] ?? 'en';

			if (headerToken.length < 1 && accessToken.length < 1 && refreshToken.length < 1) {
				return { acceptLanguage };
			}

			if (headerToken.length > 0) {
				const headerTokenResponse = await getIdentityToken(headerToken, acceptLanguage);

				if (headerTokenResponse != null) {
					return { token: headerTokenResponse, acceptLanguage };
				}
			}

			if (accessToken.length > 0) {
				const accessTokenResponse = await getIdentityToken(accessToken, acceptLanguage);

				if (accessTokenResponse != null) {
					return { token: accessTokenResponse, acceptLanguage };
				}
			}

			const refreshTokenResponse = await getIdentityToken(refreshToken, acceptLanguage);

			return { token: refreshTokenResponse, acceptLanguage };
		},
	})
);

const getIdentityToken = async (token: string, acceptLanguage: string): Promise<string | null> => {
	try {
		const headers = new Headers();
		headers.set('accept-language', acceptLanguage);
		headers.set('x-api-key', IDENTITY_SERVICE_API_KEY);
		headers.set('authorization', token);

		return (await identityServiceClient.issueServiceToken({}, { headers })).token;
	} catch (err: any) {
		if (err?.code !== 2 && DEBUG) {
			console.log('Unable to verify and issue servicing user token:', err);
		}

		return null;
	}
};

await new Promise<void>((resolve) => httpServer.listen({ port: PORT }, resolve));

console.log(`🚀 Server ready at http://localhost:${PORT}/gql`);
