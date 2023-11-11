import dotenv from 'dotenv';
import { rootDir } from './path_utils.ts';
import path from 'path';

dotenv.config({
	path: path.join(rootDir, '..', '.env'),
});

export const PORT = process.env.PORT ?? 4000;
export const DEBUG = (process.env.DEBUG ?? 'false') === 'true';
export const NODE_ENV = process.env.NODE_ENV ?? 'production';
export const ENVIRONMENT_TYPE = process.env.ENVIRONMENT_TYPE ?? 'production';

export const DATA_LOCATION = process.env.DATA_LOCATION ?? 'data';
export const KEYS_LOCATION = `${DATA_LOCATION}/keys`;
