'use strict';

const utils = require('@iobroker/adapter-core');
const https = require('https');
const fs = require('fs');
const ipInfo = require('ip');
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const graph = require('@microsoft/microsoft-graph-client');
require('isomorphic-fetch');

const oauthAuthorityHost = 'https://login.microsoftonline.com/';
const oauthAuthorizeEndpoint = 'oauth2/v2.0/authorize';
const oauthTokenEndpoint = 'oauth2/v2.0/token';
const oauthIdMetadata = 'v2.0/.well-known/openid-configuration';
const oauthScopes = ['profile','user.read','offline_access','Presence.Read'];
let updateIntervalId = null;

class MsTeams extends utils.Adapter {
    constructor(options) {
        super({
            ...options,
            name: 'ms-teams',
        });
        this.on('ready', () => {
            this.getForeignObject('system.adapter.admin.0',  (err, obj) => {
                this.onReady.bind(this)(obj.native.port || 8081);
            });
        });
        this.on('unload', this.onUnload.bind(this));
    }

    async onReady(adminPort) {
        const adapter = this;
        let currentUser = null;
        const users = {};

        let proxyConnected = false;
        let proxyPort = parseInt(this.config.proxyPort, 10);
        proxyPort = isNaN(proxyPort) ? this.config.proxyPort : (proxyPort >= 0 ? proxyPort : false);
        const adminConfigUrl = 'http://' + ipInfo.address() + ':' + adminPort + '/#tab-instances/config/system.adapter.ms-teams.' + adapter.instance;

        const oauthAuthorityUrl = oauthAuthorityHost + (this.config.appTenant || 'common') + '/';
        const oauthCallbackUrl = 'https://' + ipInfo.address() + ':' + proxyPort + '/auth/callback';
        const oauthSigninUrl = 'https://' + ipInfo.address() + ':' + proxyPort + '/auth/signin';

        await this.setObjectNotExistsAsync('availability', {
            type: 'state',
            common: {
                name: 'availability',
                type: 'string',
                role: 'state',
                read: true,
                write: true,
            },
            native: {},
        });
        await this.setObjectNotExistsAsync('activity', {
            type: 'state',
            common: {
                name: 'activity',
                type: 'string',
                role: 'state',
                read: true,
                write: true,
            },
            native: {},
        });

        const getAccessToken = async (req) => {
            if (!req.isAuthenticated()) {
                throw(new Error('Not authenticated'));
            }
            if (!req.user) {
                throw(new Error('No user in request'));
            }
            if (!req.user.oauthToken) {
                throw(new Error('No stored token'));
            }
            if (req.user.oauthToken.expired()) {
                req.user.oauthToken = await req.user.oauthToken.refresh();
            }
            return req.user.oauthToken.token.access_token;
        };
        function getAuthenticatedClient(accessToken) {
            return graph.Client.init({
                authProvider: (done) => {
                    done(null, accessToken);
                }
            });
        }

        const oauth2 = require('simple-oauth2').create({
            client: {
                id: this.config.appId,
                secret: this.config.appPassword
            },
            auth: {
                tokenHost: oauthAuthorityUrl,
                authorizePath: oauthAuthorizeEndpoint,
                tokenPath: oauthTokenEndpoint
            }
        });
        passport.serializeUser(function(user, done) {
            users[user.profile.oid] = user;
            done (null, user.profile.oid);
        });
        passport.deserializeUser(function(id, done) {
            done(null, users[id]);
        });
        passport.use(new OIDCStrategy(
            {
                identityMetadata: oauthAuthorityUrl + oauthIdMetadata,
                clientID: this.config.appId,
                responseType: 'code id_token',
                responseMode: 'form_post',
                redirectUrl: oauthCallbackUrl,
                allowHttpForRedirectUrl: true,
                clientSecret: this.config.appPassword,
                validateIssuer: false,
                passReqToCallback: false,
                scope: oauthScopes
            },
            async (iss, sub, profile, accessToken, refreshToken, params, done) => {
                if (!profile.oid) {
                    return done(new Error('No OID found in user profile.'), null);
                }
                const oauthToken = oauth2.accessToken.create(params);
                users[profile.oid] = { profile, oauthToken };
                return done(null, users[profile.oid]);
            }
        ));

        const app = express();
        app.set('port', proxyPort);
        app.use(session({
            secret: 'dsakbb12-adsj78lkn-klmsda',
            resave: false,
            saveUninitialized: false,
            unset: 'destroy'
        }));
        app.use(express.json());
        app.use(express.urlencoded({ extended: false }));
        app.use(cookieParser());
        app.use(passport.initialize());
        app.use(passport.session());
        app.use(async function(req, res, next) {
            if (req.session && req.user) {
                const update = async () => {
                    try {
                        const client = getAuthenticatedClient(await getAccessToken(req));
                        const presence = await client.api('/me/presence').version('beta').get();
                        if (req && req.session) {
                            req.session.presence = presence;
                        }
                        adapter.setState('availability', presence.availability);
                        adapter.setState('activity', presence.activity);
                        adapter.setState('info.connection', true, true);
                        currentUser = req.user;
                    } catch (err) {
                        adapter.setState('info.connection', false, true);
                        currentUser = null;
                        adapter.log.error('Failed to get presence: ' + err);
                    }
                };
                updateIntervalId = setInterval(update, (adapter.config.updateInterval || 10) * 1000);
                update();
            }
            next();
        });

        app.use('/auth/signin', function  (req, res, next) {
            passport.authenticate('azuread-openidconnect',
                {
                    response: res,
                    prompt: 'login',
                    failureRedirect: '/',
                    successRedirect: '/'
                }
            )(req,res,next);
        });
        app.use('/auth/callback', function(req, res, next) {
            passport.authenticate('azuread-openidconnect',
                {
                    response: res,
                    failureRedirect: '/',
                    successRedirect: '/'
                }
            )(req,res,next);
        });
        app.use('/', function  (req, res) {
            res.redirect(adminConfigUrl);
        });

        const server = https.createServer({
            key: fs.readFileSync(__dirname + '/key.pem'),
            cert: fs.readFileSync(__dirname + '/cert.pem')
        }, app);
        server.listen(proxyPort);
        server.on('error', (error) => {
            if (error.syscall !== 'listen') {
                throw error;
            }
            const bind = typeof proxyPort === 'string' ? 'Pipe ' + proxyPort : 'Port ' + proxyPort;
            switch (error.code) {
                case 'EACCES':
                    this.log.error(bind + ' requires elevated privileges');
                    process.exit(1);
                    break;
                case 'EADDRINUSE':
                    this.log.error(bind + ' is already in use');
                    process.exit(1);
                    break;
                default:
                    throw error;
            }
        });
        server.on('listening', () => {
            const addr = server.address();
            this.log.info('Listening on ' + (typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port));
            proxyConnected = true;
        });

        adapter.on('message', function(msg) {
            switch (msg.command) {
                case 'getStatusInfo':
                    adapter.sendTo(msg.from, msg.command, { proxyConnected, currentUser, oauthSigninUrl }, msg.callback);
                    break;
            }
        });
        adapter.setState('info.connection', false, true);
    }

    onUnload(callback) {
        try {
            clearInterval(updateIntervalId);
            callback();
        } catch (e) {
            callback();
        }
    }
}

// @ts-ignore parent is a valid property on module
if (module.parent) {
    module.exports = (options) => new MsTeams(options);
} else {
    new MsTeams();
}
