import express from 'express';
import http from 'http';
import path from 'path';
import { readFileSync } from 'fs';
import { ApolloGateway } from '@apollo/gateway';
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
import { decodeToken, ensureKeysPresent } from './jwt/jwt.ts';
import { rootDir } from './path_utils.ts';
import { DEBUG, NODE_ENV, PORT } from './environment.ts';

ensureKeysPresent();

const app = express();
const httpServer = http.createServer(app);

const supergraphPath = path.join(rootDir, '..', 'supergraph.graphql');

const gateway = new ApolloGateway({
	debug: DEBUG,
	supergraphSdl: readFileSync(supergraphPath).toString(),
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
			const tokenClaims = await decodeToken(token);

			return { tokenClaims };
		},
	})
);

await new Promise<void>((resolve) => httpServer.listen({ port: PORT }, resolve));

console.log(`🚀 Server ready at http://localhost:${PORT}/gql`);
