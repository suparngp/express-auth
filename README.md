express-auth
============

An express middleware for header based authorization. Handles the sessions seamlessly with any datastore (with correct configuration and driver).

Configuration
----
        The following configuration options are available. Override the store with your datastore option. Currently configured with mongoDB.
        <pre>
            <code>
                var defaultConfig = {
                    secret: '',
                    header: 'authorization',
                    exclude: [],
                    error: new Error('Unauthorized'),
                    userIdField: 'userId',
                    userIdRequired: true,
                    store: {
                        db: 'test',
                        host: 'localhost',
                        port: '27017',
                        username: '',
                        password: '',
                        collection: 'session',
                        w: 1,
                        expiration: 7200
                    }
                };
            </code>
        </pre>