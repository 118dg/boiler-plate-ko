if(process.env.NODE_ENV === 'production'){
    module.exports = require('./prod'); //배포(deploy) 후 production
} else {
    module.exports = require('./dev'); //local 환경에서 development
}