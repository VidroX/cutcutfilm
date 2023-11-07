import express from 'express';
import dotenv from 'dotenv';
import http from 'http';
import path from 'path';
import { readFileSync } from 'fs';
import { ApolloGateway } from '@apollo/gateway';
import { ApolloServer } from '@apollo/server';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import { expressMiddleware } from '@apollo/server/express4';
import bodyParser from 'body-parser';
import cors from 'cors';
import { fileURLToPath } from 'url';
import {
	ApolloServerPluginInlineTraceDisabled,
	ApolloServerPluginLandingPageDisabled,
	ApolloServerPluginUsageReportingDisabled,
} from '@apollo/server/plugin/disabled';
import { ApolloServerPluginInlineTrace } from '@apollo/server/plugin/inlineTrace';
import responseCachePlugin from '@apollo/server-plugin-response-cache';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
	path: path.join(__dirname, '..', '.env'),
});

const port = process.env.PORT ?? 4000;
const debug = (process.env.DEBUG ?? 'false') === 'true';
const nodeEnv = process.env.NODE_ENV ?? 'production';

const app = express();
const httpServer = http.createServer(app);

const supergraphPath = path.join(__dirname, '..', 'supergraph.graphql');

const gateway = new ApolloGateway({
	debug,
	supergraphSdl: readFileSync(supergraphPath).toString(),
});

const debugPlugins = debug
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
	nodeEnv,
	includeStacktraceInErrorResponses: debug,
	introspection: debug,
	plugins: [
		...debugPlugins,
		responseCachePlugin(),
		ApolloServerPluginDrainHttpServer({ httpServer }),
	],
});

await server.start();

const allowedOrigins = [
	`http://localhost:${port}`,
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
		context: async ({ req }) => ({
			token: (req.headers.authorization ?? '').trim().replace('Bearer ', ''),
		}),
	})
);

await new Promise<void>((resolve) => httpServer.listen({ port }, resolve));

console.log(`🚀 Server ready at http://localhost:${port}/gql`);
