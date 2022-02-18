import { Authenticator } from './authenticator';
import * as args from 'args';

args
  .option('secret', 'secret from generate')
  .option('hotp', 'code from Google Authenticator');
 
const flags = args.parse(process.argv);
const { secret, hotp } = flags;
if (!secret || !hotp) {
  throw Error("require --secret, --hotp");
}

const auth = new Authenticator();
auth.secret = secret;
console.log(`login success?: ${auth.isLoginValid(new Number(hotp).toString())}`);