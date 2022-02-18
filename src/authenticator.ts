import * as crypto from 'crypto';
import * as hiBase32 from 'hi-base32';

export class Authenticator {

    private _secret: string = "";

    constructor() {

    }

    set secret(secret: string) {
        this._secret = secret;
    }

    public generateNewSecret(): string {
        const randomBuffer = crypto.randomBytes(20);
        return hiBase32.encode(randomBuffer).replace(/=/g, '');
    }

    public isLoginValid(hOTP: string): boolean {
        const hOtpResult = this.generateHOTP();
        if (hOTP === hOtpResult) return true;
        return false;
    }

    private dynamicTruncation(hmacValue: Buffer): number {
        const offset = hmacValue[hmacValue.length - 1] & 0xf
        return (
            ((hmacValue[offset] & 0x7f) << 24) |
            ((hmacValue[offset + 1] & 0xff) << 16) |
            ((hmacValue[offset + 2] & 0xff) << 8) |
            (hmacValue[offset + 3] & 0xff)
        )
    }

    private generateHOTP(): string {
        if (!this._secret) throw Error("please set secret");
        let counter = Math.floor(Date.now() / 30000);
        const decodedSecret = hiBase32.decode.asBytes(this._secret);
        
        // สร้าง Buffer จาก counter
        const buffer = Buffer.alloc(8);
        for (let i = 0; i < 8; i++) {
            buffer[7 - i] = counter & 0xff
            counter = counter >> 8
        }

        // Step 1: Generate an HMAC-SHA-1 value
        const hmac = crypto.createHmac('sha1', Buffer.from(decodedSecret));
        hmac.update(buffer);
        const hmacResult = hmac.digest();

        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        const code = this.dynamicTruncation(hmacResult);

        // Step 3: Compute an HOTP value
        const hOtp = code % 10 ** 6;
        return `${hOtp}`;
    }

}