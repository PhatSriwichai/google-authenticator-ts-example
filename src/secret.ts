import { Authenticator } from './authenticator';

const auth = new Authenticator();
console.log(auth.generateNewSecret());