export interface ContextUser {
	userId: string;
	permissions: Permission[];
}

export interface Permission {
	action: string;
	description: string;
}
