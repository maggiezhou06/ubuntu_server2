require('dotenv').config();
const express = require("express");
const app = express();
const bodyparser = require("body-parser");
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const helpers = require('./helpers');
const jwt = require('jsonwebtoken');
const moveFile = require('move-file');
const crypto = require('crypto');

app.use(bodyparser.json());
app.use(bodyparser.urlencoded());
app.use(bodyparser.urlencoded({ extended: true }));

const accounts = require('./config');

var key = fs.readFileSync('key.pem');
var cert = fs.readFileSync('cert.pem');
var options = {
  key: key,
  cert: cert,
};
var https = require('https');
var host = 443;
var port = "0.0.0.0";
https.createServer(options, app).listen(host, port, function (err) {
  if (err) {
    console.log(err)
    return
  }
  console.log('Listening at ' + host + ': ' + port + '\n')
});

app.get("/api/listAccounts", (req, res) => {
  accounts.query('SELECT * FROM listOfUsers', (error, result) => {
    if (error) throw error;

    res.send(result);
  });
});

app.post("/api/validateUsername", (req, res) => {
  const account_Username = req.body.Username;
  accounts.query('SELECT Username FROM listOfUsers WHERE Username = ?', account_Username, (error, result) => {
    if (result.length === 0) {
       console.log("valid username");
       res.sendStatus(200);
    } else {
       console.log("username taken");
       res.sendStatus(401);
    }
  });
});

app.post("/api/addAccount", (req, res) => {
  const account = req.body;
  accounts.query('INSERT INTO listOfUsers SET ?', req.body, (error, result) => {
    if (error) throw error;
    res.send("successfully added");
  });
});

app.post('/api/getFirstName', (req, res) => {
   const account_Username = req.body.Username;
   accounts.query('SELECT First_Name FROM listOfUsers WHERE Username = ?', account_Username, (error, result) => {
     if (result.length === 0 || account_Username==='') {
       res.sendStatus(401);
     } else {
       res.send(result);
    }
  });
})

app.post('/api/getLastName', (req, res) => {
   const account_Username = req.body.Username;
   accounts.query('SELECT Last_Name FROM listOfUsers WHERE Username = ?', account_Username, (error, result) => {
     if (result.length === 0 || account_Username==='') {
       res.sendStatus(401);
     } else {
       res.send(result);
    }
  });
})

let refreshTokens = [];

app.post('/api/token', (req, res) => {
  console.log("entered /api/token");
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    console.log("got new access token");
    res.json({ accessToken: accessToken });
  });
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60m' });
};

app.post('/api/findUser', (req, res) => {
   const account_Username = req.body.Username;
   const account_Password = req.body.Password;
   accounts.query('SELECT * FROM listOfUsers WHERE Username = ? and Password = ?', [account_Username,account_Password], (error, result) => {
     if (result.length === 0 || account_Username==='' || account_Password==='') {
       console.log("invalid account");
       res.sendStatus(401);
     } else {
       console.log("valid account");
       const user = { name: account_Username }
       const accessToken = generateAccessToken(user)
       //const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
       //refreshTokens.push(refreshToken)
       //console.log("my tokens in refreshTokens: " + refreshTokens)
       //res.json({ accessToken: accessToken, refreshToken: refreshToken })
       res.json({ accessToken: accessToken })
    }
  });
})

app.delete('/api/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log("invalid access token")
      return res.sendStatus(403)
    }
    console.log("valid access token");
    req.user = user;
    next()
  })
}

const imageFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image")) {
    cb(null, true);
  } else {
    cb("Please upload only images.", false);
  }
};

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
       cb(null, 'uploads/');
    },

   // By default, multer removes file extensions so let's add them back
    filename: function(req, file, cb) {
        cb(null, file.originalname);
    }
});

var uploadFile = multer({ storage: storage, fileFilter: imageFilter });
const uploadFiles = async (req, res) => {
  try {
    console.log(req.body.Username);
    console.log(req.body.firstName);
    console.log(req.body.lastName);
    console.log(req.files);

    if (req.files == undefined) {
      return res.send(`You must select a file.`);
    }

    for(var i = 0; i < req.files.length; i++){
      var dir = "uploads/" + req.body.Username;

      if (!fs.existsSync(dir)){
        fs.mkdirSync(dir);
      }
      var oldPath= "uploads/" + req.files[i].filename;
      var getType = req.files[i].filename.split('.')[1];
      var timeStamp = Date.now().toString();
      var timeStampLength = timeStamp.length;
      var myTimeStamp = timeStamp.substring(timeStampLength-4);
      if (getType == undefined) {
        var newPath= dir + "/" + req.body.firstName + "_" + req.body.lastName + "_" + myTimeStamp + i + ".jpeg";
      } else {
        var newPath= dir + "/" + req.body.firstName + "_" + req.body.lastName + "_" + myTimeStamp + i + "." + getType;
      }
      moveFile(oldPath, newPath);
    }
    return res.send(`File has been uploaded.`);
  } catch (error) {
    console.log(error);
    return res.send(`Error when trying to upload images: ${error}`);
  }
};

app.post('/api/uploadImages', authenticateToken, uploadFile.array('file', 10), uploadFiles);

app.post('/api/getNonce', (req, res) => {
    console.log("entered getNonce");
    if (req.body.Username != null) {
      global.listOfNonces = []
      var nonce = (crypto.randomBytes(16).toString('base64'));
      while (nonce.indexOf('+') > -1){
        nonce = (crypto.randomBytes(16).toString('base64'));
      }
      console.log("final nonce: " + nonce);
      //global.nonceStart = Date.now();
      listOfNonces[req.body.Username + "-" + nonce] = Date.now();
      console.log(listOfNonces[req.body.Username + "-" + nonce] + ": item in array-" + req.body.Username + "-" + nonce);
      //listOfNonces.push(nonce);
      res.send(nonce);
    } else {
      res.sendStatus(401);
    }
});

function ensureAuthenticated(req, res, next) {
    console.log("entered ensureAuthenticated");
    console.log("req.query.token: " + req.query.token);
    console.log("req.query.username: " + req.query.username);
    if (req.query.token != null) {
      for (var key in listOfNonces) {
        console.log("time difference: " + (Date.now()-listOfNonces[key]));
        if ((Date.now()-listOfNonces[key]) > 30000) {
          delete listOfNonces[key];
        }
      }
      for (var key in listOfNonces) {
        console.log("req.query.username-req.query.token: " + req.query.username + "-" + req.query.token);
        console.log("key: " + key);
        if ((req.query.username + "-" + req.query.token) == key) {
          console.log("token valid");
          return next();
        }
      }
    }
    res.sendStatus(403);
}

app.use('/public', ensureAuthenticated);
app.use('/public', express.static(path.join(__dirname +'/uploads')));

/*
const loggingMiddleware = (req, res, next) => {
  console.log('ip:', req.ip);
  console.log('url:', req.url);
  console.log('method:', req.method);
  next();
}

app.use(loggingMiddleware);
*/

app.post('/api/getFiles', authenticateToken, (req, res) => {
    const account_Username = req.body.Username;
    var myFiles = [];
    //joining path of directory
    const directoryPath = path.join(__dirname, "/uploads/" + account_Username);
    //passsing directoryPath and callback function
    fs.readdir(directoryPath, function (err, files) {
        //handling error
        if (err) {
            console.log('Unable to scan directory: ' + err);
            return res.send('Error scanning directory: ' + err);
        }
        //listing all files using forEach
        files.forEach(function (file) {
            // Do whatever you want to do with the file
            //console.log("/" + account_Username + "/" + file);
            myFiles.push("/" + account_Username + "/" + file);
        });
        for (var i = 0; i < 2; i++) {
          console.log(myFiles[i]);
        }
        return res.json({ myFiles });
    });
});

app.post('/api/deleteFiles', (req, res) => {
    const account_Username = req.body.Username;
    var myFiles = req.body.filesForDeletion;
    for (var i = 0; i < myFiles.length; i++) {
      console.log(myFiles[i]);
      fs.unlink(myFiles[i], (err) => {
      if (err) {
        console.error(err)
        return res.send('Error deleting file: ' + err);
      }
      })
   }
   res.send("file/s removed");
});
