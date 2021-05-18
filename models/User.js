const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true, //스페이스를 없애줌
    unique: 1
  },
  password: {
    type: String,
    minlength: 5
  },
  lastname: {
      type: String,
      maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,
  token: {
    type: String //유효성 검사할 때
  },
  tokenExp: {
    //토큰을 사용할 수 있는 기간
    type: Number
  }
})

userSchema.pre('save', function (next) {
    var user = this;
    if (user.isModified('password')) {
        //비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function (err, salt) {
            if (err) return next(err)

            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) return next(err)
                user.password = hash
                next()
            })
        })
    } else {
        next()
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {

  //plainPassword: support 암호화된 비밀번호 $2b$10$O3mEinviBbUR/1yB0cbfsuKYIl5UvstslOw3vvMapa6jZ4wFJJeT.
  bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
    if(err) return cb(err),
    cb(null, isMatch)
  })
}

userSchema.methods.generateToken = function (cb) {
  var user = this;

  // jsonwebtoken을 이용해서 token을 생성하기 
  var token = jwt.sign(user._id.toHexString(), 'secretToken')
  // user._id + 'secretToken' = token 
  // -> 
  // 'secretToken' -> user._id

  user.token = token //user 필드의 token에 넣어주기
  user.save(function (err, user) {
      if (err) return cb(err)
      cb(null, user)
  })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }