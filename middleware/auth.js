const { User } = require('../models/User');

let auth = (req, res, next) => {
    //인증 처리를 하는곳 

    //클라이언트 쿠키에서 토큰을 가져온다.
    let token = req.cookies.x_auth; //x_auth라는 이름의 쿠키를 넣었었음

    //토큰을 복호화 한후 유저를 찾는다.
    User.findByToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json({ isAuth: false, error: true })

        //유저가 있으면 인증 Okay
        req.token = token;
        req.user = user; //유저 정보를 index.js로 넘겨줌
        next();
    })
}


module.exports = { auth };