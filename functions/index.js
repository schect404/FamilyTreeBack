const functions = require('firebase-functions');

var admin = require("firebase-admin");

var serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://familytree-15872.firebaseio.com"
});

const express = require('express');
const cors = require('cors')({
  origin: true,
});

const validateFirebaseIdToken = (req, res, next) => {
    console.log('Check if request is authorized with Firebase ID token');
  
    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
        !(req.cookies && req.cookies.__session)) {
      console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
          'Make sure you authorize your request by providing the following HTTP header:',
          'Authorization: Bearer <Firebase ID Token>',
          'or by passing a "__session" cookie.');
      res.status(403).send('Unauthorized');
      return;
    }
  
    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      console.log('Found "Authorization" header');
      // Read the ID Token from the Authorization header.
      idToken = req.headers.authorization.split('Bearer ')[1];
    
    }
    admin.auth().verifyIdToken(idToken).then((decodedIdToken) => {
      console.log('ID Token correctly decoded', decodedIdToken);
      req.user = decodedIdToken;
      return next();
    }).catch((error) => {
      console.error('Error while verifying Firebase ID token:', error);
      res.status(403).send('Unauthorized');
    });
  };

const app = express();

app.use(cors);
app.use(validateFirebaseIdToken);

exports.signUp = functions.https.onRequest((request,response)=>{
    signUp(request,response);
});

exports.app = functions.https.onRequest(app);

exports.checkEmail = functions.https.onRequest((request,response)=>{
    checkEmail(request,response);
});

checkEmail = (req,res) => {
    admin.auth().getUserByEmail(req.body.email)
    .then(function(userRecord) {
      return res.status(400).send({
          error: "email_already_exists"
      });
    })
    .catch(function(error) {
        if(error.code === "auth/user-not-found") res.send();
        else res.status(400).send(error);
    });
}

signUp = (req,res) => { 

    admin.auth().getUserByEmail(req.body.email)
    .then(function(userRecord) {
      return res.status(400).send({
          error: "email_already_exists"
      });
    })
    .catch(function(error) {
        if(error.code === "auth/user-not-found") {
            let email = req.body.email;

            let password = req.body.password;

            if(password.length < 8) return res.status(400).send({
                message: "invalid_password_length"
            })

            let firstName = req.body.firstName;

            let lastName = req.body.lastName;

            let dateOfBirth = req.body.dateOfBirth;

            let sex = req.body.sex;

            admin.auth().createUser({
                email: email,
                password: password,
                displayName: firstName + " " + lastName,
                firstName: firstName,
                lastName: lastName,
                dateOfBirth: dateOfBirth,
                sex: sex
            })
            .then(function(userRecord) {
                return admin.database().ref(`/users/${userRecord.uid}`).set({
                    email: userRecord.email,
                    firstName:firstName,
                    lastName:lastName,
                    dateOfBirth: dateOfBirth,
                    sex: sex
                  }).then((snapshot) => {
                    return res.send('ok');
                  });
            })
            .catch(function(error) {
                console.log(error);
                res.status(400).send(error);
            }) 
        }
    });
};