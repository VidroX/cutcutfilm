import express from 'express';
import dotenv from 'dotenv';
import http from 'http';
import path from 'path';
import { watch } from 'fs';
import { promises as fs } from 'fs';
import { ApolloGateway } from '@apollo/gateway';
import { ApolloServer } from '@apollo/server';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import { expressMiddleware } from '@apollo/server/express4';
import bodyParser from 'body-parser';
import cors from 'cors';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
	path: '../.env',
});

const port = process.env.PORT ?? 4000;

const app = express();
const httpServer = http.createServer(app);

const supergraphPath = path.join(__dirname, '..', 'supergraph.graphql');

const gateway = new ApolloGateway({
	async supergraphSdl({ update, healthCheck }) {
		const watcher = watch(supergraphPath);

		watcher.on('change', async () => {
			try {
				const updatedSupergraph = await fs.readFile(supergraphPath, 'utf-8');

				await healthCheck(updatedSupergraph);

				update(updatedSupergraph);
			} catch (e) {
				console.error(e);
			}
		});

		return {
			supergraphSdl: await fs.readFile(supergraphPath, 'utf-8'),

			async cleanup() {
				watcher.close();
			},
		};
	},
});

const server = new ApolloServer({
	gateway,
	includeStacktraceInErrorResponses: false,
	plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
});

await server.start();

app.use(
	'/gql',
	cors(),
	bodyParser.json({ limit: '10mb' }),
	expressMiddleware(server, {
		context: async ({ req }) => ({ token: req.headers.token }),
	})
);

await new Promise<void>((resolve) => httpServer.listen({ port }, resolve));

console.log(`🚀 Server ready at http://localhost:${port}/gql`);
