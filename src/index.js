/**
 * Created by jnk on 14.01.16.
 */

import Hashids from 'hashids';
import moment from 'moment';
import crypto from 'crypto';
import msgpack from 'msgpack';
import util from 'util';

export default class SuperToken {

    /**
     * Initialize the SuperToken Class
     * @param opts Object with the following required keys: secret, password, salt; optional keys: alphabet, algorithm
     */
    constructor(opts) {
        this._opts = opts || {};
        if (util.isString(this._opts.secret)) {
            this.secret = this._opts.secret;
        }else {
            throw new Error('secret needs to be set - this is used for generating the hmac');
            return;
        }

        if (util.isString(this._opts.password)) {
            this.password = this._opts.password;
        }else {
            throw new Error('password needs to be set - this is used for encrypting the token');
            return;
        }

        if (util.isString(this._opts.salt)) {
            this.salt = this._opts.salt;
        }else {
            throw new Error('salt needs to be set - this is used for salting the hash');
            return;
        }

        this.alphabet = this._opts.alphabet || 'qwertzuiopasdfghjklyxcvbnm_QWERTZUIOPASDFGHJKLYXCVBNM1234567890';
        this.algorithm = this._opts.algorithm || 'aes-256-ctr';
        this.hid = new Hashids(this.salt, 32, this.alphabet);
    }

    /**
     * Create a token
     * @param accountType required string - The account type
     * @param accountId required integer - The account id
     * @param accountParams optional object - Pass along parameters of the account (account roles etc.)
     * @param tokenParams optional object - Pass along token parameters (token use etc.)
     * @returns {String}
     */
    encode(accountType, accountId, accountParams, tokenParams) {
        if (!accountType) {
            throw new Error('accountType must not be empty');
            return '';
        }
        if (!accountId) {
            throw new Error('accountId must not be empty');
            return '';
        }
        let payload = [[accountType, accountId], accountParams || {}];
        tokenParams = tokenParams || {};

        // token expires after min 60 secs, max 750 hours (~month)
        let e = tokenParams.expires || 900;
        let otp = {};
        if (e < 60) {
            e = 60;
        } else if (e > 3600 * 750) {
            e = 3600 * 750;
        }
        otp.ea = moment().add(e, 's').unix(); // expiresAt
        otp.ed = e; // expire delta
        otp.v = 1;  // version
        otp.ex = 0;

        if (!tokenParams.use || typeof tokenParams.use !== 'string') {
            otp.u = 'auth';
        } else {
            otp.u = tokenParams.use;
        }

        payload.push(otp);
        payload.push(this._payloadSignature(payload));

        // pack payload into buffer
        let packedToken = msgpack.pack(payload);
        // encrypt buffer data
        let encryptedToken = this._encrypt(packedToken);
        // convert data to hex string
        let hexToken = encryptedToken.toString('hex');
        // shorten with hashids
        let token = this.hid.encodeHex(hexToken);

        return {
            token: token,
            expiresAt: moment().add(e, 'seconds').format(),
        };
    }

    /**
     * Decodes and verifies a token and returns the result
     * @param token required string - The token to validate
     * @returns {Object}
     */
    decode(token) {
        let output = {
            isValid() {
                return this._valid && this.errors.length === 0;
            },
            isAdmin(withRoles) {
                if (this.isValid() && this.isType('admin')) {
                    if (withRoles) {
                        return this.hasRole(withRoles);
                    } else {
                        return true;
                    }
                }
                return false;
            },
            hasRole(withRoles) {
                if (this.isValid()) {
                    if (withRoles) {
                        withRoles = typeof withRoles === 'string' ? [withRoles] : withRoles;
                        let roles = this.account.roles || [];
                        if (withRoles.length > 0) {
                            if (roles.indexOf('root') !== -1) {
                                return true;
                            }
                            for (let role of withRoles) {
                                if (roles.indexOf(role) !== -1) {
                                    return true;
                                }
                            }
                        }
                    } else {
                        return true;
                    }
                }
                return false;
            },
            isUser(withRoles) {
                if (this.isValid() && this.isType('user')) {
                    if (withRoles) {
                        return this.hasRole(withRoles);
                    } else {
                        return true;
                    }
                }
                return false;
            },
            isType(type) {
                return this.isValid() && type === this._type
            },
            hasUse(use) {
                return this.isValid() && this.token.use === use;
            },
            isTypeWithUse(type, use) {
                return this.isValid() && this.isType(type) && this.hasUse(use);
            },
            _valid: false,
            _type: null,
            account: {},
            token: {raw: token},
            errors: [],
        };

        let inputToken = null;

        if (token) {
            try {
                // hashed token to hex string
                let hexToken = this.hid.decodeHex(token);
                // hex string to buffer, decrypt buffer
                let decryptedToken = this._decrypt(new Buffer(hexToken, 'hex'));
                // unpack decrypted data
                inputToken = msgpack.unpack(decryptedToken);
            } catch (e) {

            }
        }

        if (inputToken && inputToken.length === 4) {
            // check signature
            let tokenSignature = inputToken.splice(3, 1)[0];
            let checkSignature = this._payloadSignature(inputToken);
            if (checkSignature === tokenSignature) {
                // check expired
                let {0: accountInfo, 1: accountParams, 2: tokenParams} = inputToken;
                if (tokenParams.ea > moment().unix()) {
                    // set data
                    output.account = accountParams;
                    output.account.id = accountInfo[1];
                    output._type = accountInfo[0];
                    output.token.createdAt = moment((tokenParams.ea - tokenParams.ed) * 1000).format();
                    output.token.expiresAt = moment(tokenParams.ea * 1000).format();
                    output.token.createdAtTimestamp = tokenParams.ea;
                    output.token.expiresAtTimestamp = tokenParams.ea;
                    output.token.expireDuration = tokenParams.ed;
                    output.token.use = tokenParams.u;
                    output._valid = true;
                } else {
                    output.token.createdAt = moment((tokenParams.ea - tokenParams.ed) * 1000).format();
                    output.token.expiresAt = moment(tokenParams.ea * 1000).format();
                    output.token.expiresAtTimestamp = tokenParams.ea;
                    output.token.createdAtTimestamp = tokenParams.ea - tokenParams.ed;
                    output.token.expireDuration = tokenParams.ed;
                    output.errors.push('token expired');
                }
            } else {
                output.errors.push('invalid signature');
            }
        }
        return output;
    }

    _payloadSignature(payload) {
        return this.hid.encodeHex(crypto.createHmac('sha256', this.secret).update(msgpack.pack(payload)).digest('hex'));
    }

    _encrypt(buffer) {
        var cipher = crypto.createCipher(this.algorithm, this.password);
        return Buffer.concat([cipher.update(buffer), cipher.final()]);
    }

    _decrypt(buffer) {
        let decipher = crypto.createDecipher(this.algorithm, this.password);
        return Buffer.concat([decipher.update(buffer), decipher.final()]);
    }
}

export default SuperToken;