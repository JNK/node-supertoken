/**
 * Created by jnk on 14.01.16.
 */

// compile before running: npm run compile

var SuperToken = require('../dist').default;

var params = {
    secret: 'superSecret',      // this is used for generating the hmac
    password: 'coolPassword',   // this is used for encrypting the token
    salt: 'awesomeSalt'         // this is used for salting the hash
};

var st = new SuperToken(params);

var token = st.encode('admin', 1, {roles:['bla'], foo: 'bar'}, {use: 'party', expires: 3600});
console.log('Generated token: %s expires at %s', token.token, token.expiresAt);

var decodedToken = st.decode(token.token);

if (decodedToken.hasUse('party')) {
    console.log('We can party!');
}

if (decodedToken.isType('admin')) {
    console.log('Admins only!');
}

if (decodedToken.hasRole('bla')) {
    console.log('Has role bla: ready to roll!');
}

console.log('Account: ', decodedToken.account, ' - Valid: ' + decodedToken.isValid());