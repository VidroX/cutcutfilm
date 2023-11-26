import {
	ApolloServerPlugin,
	BaseContext,
	GraphQLRequestContext,
	GraphQLRequestListener,
} from '@apollo/server';

export default function CookiePassthroughPlugin<
	TContext extends BaseContext,
>(): ApolloServerPlugin<TContext> {
	return {
		async requestDidStart(
			requestContext: GraphQLRequestContext<any>
		): Promise<GraphQLRequestListener<any>> {
			return {
				async willSendResponse({ response }) {
					if (
						requestContext.contextValue?.cookies == null ||
						requestContext.contextValue.cookies?.length < 1
					) {
						return;
					}

					response.http.headers.set('set-cookie', requestContext.contextValue.cookies);
				},
			};
		},
	};
}

export const parseServiceCookieString = (cookies: string): string[] =>
	cookies
		.split(' Secure, ')
		.filter((c) => c != null && c.length > 0)
		.map((c) => (c.endsWith('Secure') ? c : `${c} Secure`));
