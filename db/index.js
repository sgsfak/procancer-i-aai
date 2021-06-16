const { Pool } = require('pg')
const config = require('config')

console.log("connecting to %O", config.db);
const pool = new Pool(config.db);

module.exports = {
    query: (text, params) => {
        return pool.query(text, params)
    },
    getClient: (callback) => {
        return pool.connect();
    }
}