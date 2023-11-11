import { promises as fs } from 'fs';
import {
	generateKeyPair,
	exportPKCS8,
	exportSPKI,
	importSPKI,
	jwtVerify,
	JWTPayload,
	KeyLike,
} from 'jose';
import { KEYS_LOCATION, ENVIRONMENT_TYPE } from '../environment.ts';

const ALGO = 'ES512';

const ensureKeysPresent = async () => {
	await fs.mkdir(KEYS_LOCATION, { recursive: true });

	const { privateKey, publicKey } = await generateKeyPair(ALGO);
	const privateKeyPem = await exportPKCS8(privateKey);
	const publicKeyPem = await exportSPKI(publicKey);

	try {
		await fs.writeFile(`${KEYS_LOCATION}/private.pem`, privateKeyPem, { flag: 'wx' });
		await fs.writeFile(`${KEYS_LOCATION}/public.pem`, publicKeyPem, { flag: 'wx' });
	} catch (err: any) {
		if (err?.code === 'EEXIST') {
			return;
		}

		throw err;
	}
};

const getPublicKey = async (): Promise<KeyLike | undefined> => {
	try {
		const publicKeySPKI = await fs.readFile(`${KEYS_LOCATION}/public.pem`, 'utf-8');
		const publicKey = await importSPKI(publicKeySPKI, ALGO);

		return publicKey;
	} catch (err) {
		console.error(err);
	}
};

const getIssuer = (): string => {
	if (ENVIRONMENT_TYPE === 'production') {
		return 'https://cutcutfilm.com';
	}

	return 'https://ccf-dev.vidrox.me';
};

const decodeToken = async (token: string): Promise<JWTPayload | undefined> => {
	try {
		if (token.trim().length === 0) {
			return;
		}

		const publicKey = await getPublicKey();

		if (publicKey == null) {
			return;
		}

		const { payload } = await jwtVerify(token, publicKey, {
			algorithms: [ALGO],
			issuer: getIssuer(),
		});

		return payload;
	} catch (err) {
		console.log(err);
	}
};

export { ensureKeysPresent, decodeToken, getPublicKey };
