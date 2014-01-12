/**
 * Created by suparngupta on 1/11/14.
 */


var crypto = require('crypto'),
    Session = require('./Session');

function Authorize(req, res, options){
    Object.defineProperty(this, 'req', {value: req});
    Object.defineProperty(this, 'res', {value: res});
    Object.defineProperty(this, 'store', {value: options.store});
    Object.defineProperty(this, 'header', {value: options.header});
    Object.defineProperty(this, 'secret', {value: options.secret});
}

Authorize.prototype.createSession = function(){
    var userId;
    var callback;
    if(arguments.length === 2){
        userId = arguments[0];
        callback = arguments[1];
    }
    else{
        callback = arguments[0];
    }
    var sha256 = crypto.createHash('sha256');
    var sessionId = this.store.getId();
    sha256.update(!userId ? sessionId + new Date().toString() : userId + sessionId + new Date().toString());
    var token = sha256.digest('hex');
    var sha1 = crypto.createHash('sha1');
    sha1.update(this.secret + sessionId + token);
    var signature = sha1.digest('hex');
    var session = new Session({
        _id: sessionId,
        token: token,
        signature: signature,
        createdAt: new Date()
    });

    var self = this;
    this.store.set(session, function(err, s){
        self.session = session;
        self.res.set(self.header, session.id + ':' + session.token + ':' + signature);
        if(!callback && err){
            throw new TypeError('Unable to create session');
        }
        if(callback) callback(err, session);
    });
};

Authorize.prototype.destroySession = function(callback){
    var self = this;
    if(!self.session || !self.session.id){
        if(callback) callback(new ReferenceError('No session found'));
        else throw new ReferenceError('No session found');
    }
    else{
        self.store.destroy(self.session.id, function(err, deleted){
            self.res.set(self.header, '');
            if(!callback && err){
                throw new TypeError('Unable to destroy session');
            }
            if(callback) callback(err, deleted);
        });
    }
};

Authorize.prototype.get = function(callback){
    var self = this;
    var value = self.req.get(self.header);
    if(!value){
        if(!callback) throw new TypeError('Authorization header has unknown syntax');
        else callback(new TypeError('Authorization header has unknown syntax'));
        return;
    }
    var tokens = value.split(':');
    var sessionId = tokens[0];
    var token = tokens[1];
    var signature = tokens[2];
    if (!sessionId || !token || !signature) {
        if(!callback) throw new TypeError('Authorization header has unknown syntax');
        else callback(new TypeError('Authorization header has unknown syntax'));
        return;
    }

    self.store.get(sessionId, function(err, result){
        if(err || !result){
            if(!callback) throw new ReferenceError('No authorization token found');
            else callback(new ReferenceError('No authorization token found'));
            return;
        }
        else if(value !== self.session.id + ':' + self.session.token + ':' + self.session.signature){
            if(!callback) throw new ReferenceError('Token Tampered');
            else callback(new ReferenceError('Token Tampered'));
            return;
        }
        self.session = new Session(result);
        self.res.set(self.header, session.value);
        if(callback) callback(err, session);
    });
};
module.exports = Authorize;