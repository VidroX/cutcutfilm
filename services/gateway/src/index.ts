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

	const parsedKeySet = JSON.parse(
		Buffer.from(identityKeySet.encodedKeys, 'base64').toString('utf8')
	);

	keySet = parsedKeySet;
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
	],
});

await server.start();

const allowedOrigins = [
	`http://localhost:${PORT}`,
	'http://localhost',
	'https://ccf-dev.vidrox.me',
	'https://cutcutfilm.com',
];

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
	}),
	bodyParser.json({ limit: '10mb' }),
	expressMiddleware(server, {
		context: async ({ req }) => {
			const token = (req.headers.authorization ?? '').trim().replace('Bearer ', '');

			if (token.trim().length < 1) {
				return { acceptLanguage: req.headers['accept-language'] ?? 'en' };
			}

			try {
				const headers = new Headers();
				headers.set('accept-language', req.headers['accept-language'] ?? 'en');
				headers.set('x-api-key', IDENTITY_SERVICE_API_KEY);
				headers.set('authorization', token);

				const resp = await identityServiceClient.issueServiceToken({}, { headers });

				return { token: resp.token, acceptLanguage: req.headers['accept-language'] ?? 'en' };
			} catch (err: any) {
				if (err?.code !== 2 && DEBUG) {
					console.log('Unable to verify and issue servicing user token:', err);
				}

				return { acceptLanguage: req.headers['accept-language'] ?? 'en' };
			}
		},
	})
);

await new Promise<void>((resolve) => httpServer.listen({ port: PORT }, resolve));

console.log(`🚀 Server ready at http://localhost:${PORT}/gql`);
