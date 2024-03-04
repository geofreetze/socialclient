/*

	HUGE SHOUTOUT to Brad Traversy
		the skeleton of this code was based on Brad's free neo4j course
			https://www.eduonix.com/courses/Web-Development/learn-to-build-apps-using-neo4j
			https://www.youtube.com/watch?v=RE2PLyFqCzE - Deploy Node.js App To Digital Ocean Server


	Medium Shoutout to Chris Courses
		Chris taught me how to use passport.js for the login system
			Node Authentication Tutorial with Passport.js
			https://www.youtube.com/watch?v=gYjHDMPrkWU&list=PLpPnRKq7eNW3Qm2OfoJ3Hyvf-36TulLDp


	small shoutout to Ben Awad
		Ben taught me how to automatically send login emails using nodemailer
			https://www.youtube.com/watch?v=YU3qstG74nw - How to Send an Email in Node.js

*/

const MAX_ADD_COUNT = 300; // this is a security feature. if you add too many things, the tripwire locks you out
const MAX_SWIPE_COUNT = 50; // you should only swipe so many people a day. you should incentivize people to only swipe on those they're serious about
const MAX_MATCH_COUNT = 999; // users get their top matches.


var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
var jwt = require('jsonwebtoken');
var neo4j = require('neo4j-driver').v1;
var request = require('request');
const expressValidator = require('express-validator');
const flash = require('connect-flash');
var session = require('express-session');
var passport = require('passport');
var sessionstore = require('sessionstore');
const fs = require('fs'); // https://stackabuse.com/writing-to-files-in-node-js/
const mathjs = require('mathjs');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// about.ejs carasoul imgs
var publicDir = require('path').join(__dirname, '/public');
app.use(express.static(publicDir));

// misc middleware
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


// express-session middleware with sessionstore
app.use(session({
    store: sessionstore.createSessionStore(),
    secret: EXPRESS_SESSIONSTORE_SECRET, 
    resave: false,
    saveUninitialized: false
    //cookie: { secure: true }
}));

// passport middleware
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

// connect-flash middleware
app.use(require('connect-flash')());
app.use(function (req, res, next) {
  res.locals.messages = require('express-messages')(req, res);
  next();
});

// express-validator middleware
app.use(expressValidator({
    errorFormatter: function(param, msg, value) {
        var namespace = param.split('.')
        , root    = namespace.shift()
        , formParam = root;

        while(namespace.length) {
            formParam += '[' + namespace.shift() + ']';
        }
        return {
            param : formParam,
            msg   : msg,
            value : value
        };
    }
}));

// neo4j middleware
var driver = neo4j.driver("bolt://"+IP_ADDRESS, neo4j.auth.basic(NEO4J_USERNAME, NEO4J_PASSWORD));
var neo4j_session = driver.session();


var ACCEPTED_EMAIL_DOMAINS;
var BLACKLISTED_EMAILS;
var GUESTLIST_EMAILS;




// this code is used to backup the database
//
// How to Make a backup:
//     run the following neo4j commands
//         MATCH (u:User) RETURN u.email, u.addCount
//         MATCH (u:User)-[r:HAS]-(t:Tag) RETURN t.description, u.email ORDER BY t.description
//     save that data on some Google spreadsheet
//     note: the strings should have quotations marks around them. i included substring(1, str.length-1) in the code to account for this
//..........
// Restoring a backup:
//     open /backupuser /backuptag
//     paste in the data from the Google spreadsheet
//     type the password hit enter
//




// YouTube Route
app.get('/youtube', function (req, res) {
	res.redirect('https://www.youtube.com/channel/UCX5rZqDDY4MdXEj8Cu40Afg/videos');
});




// User Count Route
app.get('/usercount', function (req, res) {

    neo4j_session
        .run("MATCH (u:User) RETURN u.email ORDER BY reverse(u.email)")
        .then(function (result3) {

                            var unsortedKindredArr = [];

                            result3.records.forEach(function (record) {
                                if (record._fields[0] != null) {
				    var str = record._fields[0].toString();
                                    unsortedKindredArr.push({ email: str.substring(str.indexOf("@") + 1) });
                                }
                            });


                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedKindredArr = unsortedKindredArr.reduce((all, record) => {

                                var user = all.find(u => u.email === record.email);

                                if (user) {
                                    user.count += 1;
                                } else all.push({
                                    email: record.email,
				    count: 1
                                });

                                return all;
                            }, []).sort((a, b) => b.count - a.count);

				neo4j_session.close();

				res.render('usercount', {
				    userCount: result3.records.length,
				    collegeAll: sortedKindredArr
				});

        })
        .catch(function (error) {
            console.log(error);
        });
});




// Berkeley Count Route
app.get('/berkeleycount', function (req, res) {

    neo4j_session
        .run("MATCH (u:User) WHERE u.email ENDS WITH '@berkeley.edu' RETURN COUNT(u)")
        .then(function (result3) {

				neo4j_session.close();

				res.render('berkeleycount', {
				    berkeleyCount: result3.records[0]._fields[0].low
				});

        })
        .catch(function (error) {
            console.log(error);
        });
});




// reset count
app.get('/resetcount', isAdmin(), function (req, res) {
	res.render('resetcount');
});
app.post('/resetcount', isAdmin(), function (req, res) {
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {
            neo4j_session
                .run("MATCH (u:User) SET u.addCount = 0, u.addFriendCount = 0")
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });

	res.redirect('/resetcount');

    } else {
	res.send('incorrect password');
    }

});




// add guest
app.get('/addguest', isAdmin(), function (req, res) {
	res.render('addguest');
});
app.post('/addguest', isAdmin(), function (req, res) {
    var email = req.body.email;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	fs.appendFile('guestlist.txt', email + "\n", (err) => {
    		if (err) throw err;
	});

	res.redirect('/addguest');

    } else {
	res.send('incorrect password');
    }

});



/*
// Backup Print Database Route
app.get('/backupprintdatabase', isAdmin(), function (req, res) {

    neo4j_session
        .run("MATCH (u:User)-[r:HAS]-(t:Tag) RETURN u.email, r.weight, t.description ORDER BY toUpper(t.description)")
        .then(function (result4) {
            var tagArrAll = [];
            result4.records.forEach(function (record) {
                tagArrAll.push({
                    user: record._fields[1].low
                    description: record._fields[0],
                });
            });

    neo4j_session
        .run("MATCH (u:User) RETURN u.email ORDER BY reverse(u.email)")
        .then(function (result3) {

                            var unsortedKindredArr = [];

                            result3.records.forEach(function (record) {
                                if (record._fields[0] != null) {
				    var str = record._fields[0].toString();
                                    unsortedKindredArr.push({ email: str.substring(str.indexOf("@") + 1) });
                                }
                            });


                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedKindredArr = unsortedKindredArr.reduce((all, record) => {

                                var user = all.find(u => u.email === record.email);

                                if (user) {
                                    user.count += 1;
                                } else all.push({
                                    email: record.email,
				    count: 1
                                });

                                return all;
                            }, []).sort((a, b) => b.count - a.count);

    neo4j_session
        .run("MATCH (u:User)-[r:HAS]-(:Tag) RETURN u.email, COUNT(r) ORDER BY COUNT(r) DESC")
        .then(function (result2) {

                            var unsortedOptInArr = [];

                            result2.records.forEach(function (record) {
                                if (record._fields[0] != null) {
                                    unsortedOptInArr.push({ email: record._fields[1].low.toString() });
                                }
                            });


		            var optInCount = 0;

                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedOptInArr = unsortedOptInArr.reduce((all, record) => {

                                optInCount += parseInt(record.email);
                                var user = all.find(u => u.email === record.email);

                                if (user) {
                                    user.count += 1;
                                } else all.push({
                                    email: record.email,
				    count: 1
                                });

                                return all;
                            }, []).sort((a, b) => parseInt(a.email) - parseInt(b.email));

				neo4j_session.close();

				res.render('index', {
				    domainName: DOMAIN_NAME,
				    userCount: result3.records.length,
				    optInCount: optInCount,
				    lurkerCount: result3.records.length - result2.records.length,
     	        		    tagsAll: tagArrAll,
				    collegeAll: sortedKindredArr,
				    optInAll: sortedOptInArr
				});

        })
        .catch(function (error) {
            console.log(error);
        });

        })
        .catch(function (error) {
            console.log(error);
        });

        })
        .catch(function (error) {
            console.log(error);
        });
});
*/



// Backup user
app.get('/backupuser', isAdmin(), function (req, res) {
	res.render('backupuser');
});
app.post('/backupuser', isAdmin(), function (req, res) {
    var email = req.body.email;
    var contact = req.body.contact;
    var latitude = req.body.latitude;
    var longitude = req.body.longitude;
    var addCount = req.body.addCount;
    var addFriendCount = req.body.addFriendCount;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	var emailArr = email.split("\r\n");
	var contactArr = contact.split("\r\n");
	var latitudeArr = latitude.split("\r\n");
	var longitudeArr = longitude.split("\r\n");
	var addCountArr = addCount.split("\r\n");
	var addFriendCountArr = addFriendCount.split("\r\n");


	var userLength = emailArr.length;
	for (i = 0; i < userLength; i++) {
            neo4j_session
                .run("CREATE (u:User { email: {emailParam}, contact: {contactParam}, latitude: {latitudeParam}, longitude: {longitudeParam}, addCount: {addCountParam}, addFriendCount: {addFriendCountParam}, allSchools: true, currentIndex: false, matchIndex: false, statementQuery: '' })", { emailParam: emailArr[i].substring(1, emailArr[i].length-1), contactParam: contactArr[i].substring(1, contactArr[i].length-1), latitudeParam: latitudeArr[i], longitudeParam: longitudeArr[i], addCountParam: addCountArr[i], addFriendCountParam: addFriendCountArr[i] })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	}

            neo4j_session
                .run("MATCH (u:User) SET u.latitude = toFloat(u.latitude), u.longitude = toFloat(u.longitude), u.addCount = toInteger(u.addCount), u.addFriendCount = toInteger(u.addFriendCount)")
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });

	res.redirect('/backupuser');

    } else {
	res.send('incorrect password');
    }
});




// Backup tag
app.get('/backuptag', isAdmin(), function (req, res) {
	res.render('backuptag');
});
app.post('/backuptag', isAdmin(), function (req, res) {
    var email = req.body.email;
    var tag = req.body.tag;
    var weight = req.body.weight;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	var emailArr = email.split("\r\n");
	var tagArr = tag.split("\r\n");
	var weightArr = weight.split("\r\n");


	var tagLength = emailArr.length;
	for (i = 0; i < tagLength; i++) {
            neo4j_session
		.run("MATCH (u:User) WHERE u.email={emailParam} MERGE (t:Tag {description:{tagParam}}) MERGE (u)-[:HAS {weight: {weightParam}} ]->(t)", { emailParam: emailArr[i].substring(1, emailArr[i].length-1), tagParam: tagArr[i].substring(1, tagArr[i].length-1), weightParam: weightArr[i] })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	}

            neo4j_session
                .run("MATCH ()-[r:HAS]-(t:Tag) SET r.weight = toFloat(r.weight)")
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });

	res.redirect('/backuptag');

    } else {
	res.send('incorrect password');
    }
});




// Rename tag
app.get('/renametag', isAdmin(), function (req, res) {
	res.render('renametag');
});
app.post('/renametag', isAdmin(), function (req, res) {
    var tag = req.body.tag;
    var rename = req.body.rename;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	var tagArr = tag.split("\r\n");
	var renameArr = rename.split("\r\n");

	var tagLength = tagArr.length;
	for (i = 0; i < tagLength; i++) {
            neo4j_session
		.run("MATCH (t:Tag) WHERE t.description={tagParam} SET t.description={renameParam}", { tagParam: tagArr[i].substring(1, tagArr[i].length-1), renameParam: renameArr[i].substring(1, renameArr[i].length-1) })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	}

	res.redirect('/renametag');

    } else {
	res.send('incorrect password');
    }
});




// Reset user location
app.get('/resetuserlocation', isAdmin(), function (req, res) {
	res.render('resetuserlocation');
});
app.post('/resetuserlocation', isAdmin(), function (req, res) {
    var email = req.body.email;
    var latitude = req.body.latitude;
    var longitude = req.body.longitude;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	var emailArr = email.split("\r\n");
	var latitudeArr = latitude.split("\r\n");
	var longitudeArr = longitude.split("\r\n");

	var tagLength = emailArr.length;
	for (i = 0; i < tagLength; i++) {
            neo4j_session
		.run("MATCH (u:User) WHERE u.email={emailParam} SET u.latitude={latitudeParam}, u.longitude={longitudeParam}", { emailParam: emailArr[i].substring(1, emailArr[i].length-1), latitudeParam: latitudeArr[i], longitudeParam: longitudeArr[i] })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	}

            neo4j_session
                .run("MATCH (u:User) SET u.latitude = toFloat(u.latitude), u.longitude = toFloat(u.longitude)")
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });

	res.redirect('/resetuserlocation');

    } else {
	res.send('incorrect password');
    }
});




// Backup relationships
app.get('/backuprelationships', isAdmin(), function (req, res) {
	res.render('backuprelationships');
});
app.post('/backuprelationships', isAdmin(), function (req, res) {
    var email1 = req.body.email1;
    var relationshipType = req.body.relationshipType;
    var email2 = req.body.email2;
    var password = req.body.password;

    if (password.localeCompare(BACKUP_PASSWORD) == 0) {

	var email1Arr = email1.split("\r\n");
	var relationshipTypeArr = relationshipType.split("\r\n");
	var email2Arr = email2.split("\r\n");


	var listLength = email1Arr.length;
	for (i = 0; i < listLength; i++) {
	    if (relationshipTypeArr[i].localeCompare("\"SWIPE\"") == 0) {
            neo4j_session
		.run("MATCH (u:User),(v:User) WHERE u.email={email1Param} AND v.email={email2Param} MERGE (u)-[:SWIPE]->(v)", { email1Param: email1Arr[i].substring(1, email1Arr[i].length-1),  email2Param: email2Arr[i].substring(1, email2Arr[i].length-1) })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	    }
	    else if (relationshipTypeArr[i].localeCompare("\"MATCH\"") == 0) {
            neo4j_session
		.run("MATCH (u:User),(v:User) WHERE u.email={email1Param} AND v.email={email2Param} MERGE (u)-[:MATCH]-(v)", { email1Param: email1Arr[i].substring(1, email1Arr[i].length-1),  email2Param: email2Arr[i].substring(1, email2Arr[i].length-1) })
                .then(function (result) {
	                neo4j_session.close();
                })
                .catch(function (error) {
                    console.log(error);
                });
	    }
	}

	res.redirect('/backuprelationships');

    } else {
	res.send('incorrect password');
    }

});



/*
// about Route
app.get('/about', isLoggedInMiddleware(), function (req, res) {
	res.render('about');
});
*/

/*
// Why Not Gmail Route
app.get('/why-not-gmail', isLoggedInMiddleware(), function (req, res) {
	res.render('why-not-gmail');
});
*/


// Catfish Route
app.get('/catfish', function (req, res) {
	res.render('catfish');
});



// Invited Route
app.get('/invite-sent', isLoggedInMiddleware(), function (req, res) {
	res.render('invite-sent');
});



/*
// Invited Route
app.get('/email-invalid', isLoggedInMiddleware(), function (req, res) {
	res.render('email-invalid');
});
*/



/*
// Index Route
app.get('/', isLoggedInMiddleware(), function (req, res) {
	res.render('index', {
	    domainName: DOMAIN_NAME
	});
});
*/



// Guest Route
app.get('/guest', isLoggedInMiddleware(), function (req, res) {
	res.render('guest', {
	    domainName: DOMAIN_NAME
	});
});



// Index Route
app.get('/', isLoggedInMiddleware(), function (req, res) {

    neo4j_session
        .run("MATCH (:User)-[r:HAS]-(t:Tag) RETURN t.description, COUNT(r) ORDER BY toUpper(t.description)")
        .then(function (result4) {
            var tagArrAll = [];
            result4.records.forEach(function (record) {
                tagArrAll.push({
                    description: record._fields[0],
                    count: record._fields[1].low
                });
            });

    neo4j_session
        .run("MATCH (u:User) RETURN u.email ORDER BY reverse(u.email)")
        .then(function (result3) {

                            var unsortedKindredArr = [];

                            result3.records.forEach(function (record) {
                                if (record._fields[0] != null) {
				    var str = record._fields[0].toString();
                                    unsortedKindredArr.push({ email: str.substring(str.indexOf("@") + 1) });
                                }
                            });


                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedKindredArr = unsortedKindredArr.reduce((all, record) => {

                                var user = all.find(u => u.email === record.email);

                                if (user) {
                                    user.count += 1;
                                } else all.push({
                                    email: record.email,
				    count: 1
                                });

                                return all;
                            }, []).sort((a, b) => b.count - a.count);

    neo4j_session
        .run("MATCH (u:User)-[r:HAS]-(:Tag) RETURN u.email, COUNT(r) ORDER BY COUNT(r) DESC")
        .then(function (result2) {

                            var unsortedOptInArr = [];

                            result2.records.forEach(function (record) {
                                if (record._fields[0] != null) {
                                    unsortedOptInArr.push({ email: record._fields[1].low.toString() });
                                }
                            });


		            var optInCount = 0;

                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedOptInArr = unsortedOptInArr.reduce((all, record) => {

                                optInCount += parseInt(record.email);
                                var user = all.find(u => u.email === record.email);

                                if (user) {
                                    user.count += 1;
                                } else all.push({
                                    email: record.email,
				    count: 1
                                });

                                return all;
                            }, []).sort((a, b) => parseInt(a.email) - parseInt(b.email));

				neo4j_session.close();

				res.render('index', {
				    domainName: DOMAIN_NAME,
				    userCount: result3.records.length,
				    optInCount: optInCount,
				    lurkerCount: result3.records.length - result2.records.length,
     	        		    tagsAll: tagArrAll,
				    collegeAll: sortedKindredArr,
				    optInAll: sortedOptInArr
				});

        })
        .catch(function (error) {
            console.log(error);
        });

        })
        .catch(function (error) {
            console.log(error);
        });

        })
        .catch(function (error) {
            console.log(error);
        });
});



app.post('/send-invite', function (req, res) {

    var email = req.body.email.toLowerCase().trim();

    // was captcha box checked?
    if(
        req.body.captcha === undefined ||
        req.body.captcha === '' ||
        req.body.captcha === null
      ){
        req.flash('danger', 'Please check the \"I\'m not a robot\" box.');
        return res.json({"success": false});
    }


    // is valid email?
    req.checkBody('email', 'Not a valid email').isEmail();
    let errors = req.validationErrors();
    if (errors) {
        req.flash('danger', 'Not a valid email.');
        return res.json({"success": false});
    }


    // is email too long?
    if (email.length > 100) {
        req.flash('danger', 'Your email is over 100 characters long.');
        return res.json({"success": false});
    }


let date_ob = new Date();
let date = ("0" + date_ob.getDate()).slice(-2);
let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
let year = date_ob.getFullYear();
let hours = date_ob.getHours();
let minutes = date_ob.getMinutes();
let seconds = date_ob.getSeconds();

    // check if person is blacklisted
    fs.readFile('blacklist.txt', function(err, data) {
	if(err) throw err;
	BLACKLISTED_EMAILS = data.toString().split("\n");
    });

    var isBlacklisted = false;
    BLACKLISTED_EMAILS.forEach( function(blacklisted_email) {
        if (email.localeCompare(blacklisted_email) == 0) {
            isBlacklisted = true;
	    //break;
        }
    });

    if (isBlacklisted) {
	fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nBLACKLIST_LOGIN_DENIED", (err) => {
    		if (err) throw err;
	});
        req.flash('danger', 'This email was blacklisted.');
        return res.json({"success": false});
    }



    // check if person is on the guest list
    fs.readFile('guestlist.txt', function(err, data) {
	if(err) throw err;
	GUESTLIST_EMAILS = data.toString().split("\n");
    });

    var isGuest = false;
    GUESTLIST_EMAILS.forEach( function(guestlist_email) {
        if (email.localeCompare(guestlist_email) == 0) {
            isGuest = true;
	    //break;
        }
    });



    // https://stackoverflow.com/questions/8885052/regular-expression-to-validate-email-ending-in-edu
    // https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_regexp_test2
    // .edu
    var patt = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.+-]+\\.edu$");
    // .edu.XX
    var patt2 = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.+-]+\\.edu\\.[a-zA-Z0-9.+-]+$");
    // .ac.XX
    var patt3 = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.+-]+\\.ac\\.[a-zA-Z0-9.+-]+$");
  

    var isCollegeEmail = false;
    if (patt.test(email) || (patt2.test(email) || patt3.test(email))) {
    	isCollegeEmail = true;
    }

    if (!isCollegeEmail && !isGuest) {
	fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nNON_COLLEGE_EMAIL_LOGIN_DENIED", (err) => {
    		if (err) throw err;
	});

        req.flash('danger', 'You are not on the guest-list.');
        return res.json({"success": false});
    }



/*
    // check if college is an the accepted domain
    fs.readFile('emailDomains.txt', function(err, data) {
	if(err) throw err;
	ACCEPTED_EMAIL_DOMAINS = data.toString().split("\n");
    });

    var isAcceptedEmailDomain = false;
    ACCEPTED_EMAIL_DOMAINS.forEach( function(email_domain) {
        if (email.substring(email.indexOf("@") + 1).localeCompare(email_domain) == 0) {
            isAcceptedEmailDomain = true;
	    //break;
        }
    });

    if (!isAcceptedEmailDomain) {
	fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nEMAIL_DOMAIN_DENIED", (err) => {
    		if (err) throw err;
	});

	fs.appendFile('deniedEmailDomains.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email, (err) => {
    		if (err) throw err;
	});

//        req.flash('danger', 'Bear with me, please. I need to manually add your college to my server list. I will email you by tomorrow, letting you know that I\'m ready for you.');
        req.flash('danger', 'Sorry, we\'re not taking new schools at this time.');
        return res.json({"success": false});
    }
*/



    // Verify URL
    const verifyUrl = `https://google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${req.body.captcha}&remoteip=${req.connection.remoteAddress}`;

    // Make Request To VerifyURL
    request(verifyUrl, (err, response, body) => {
        body = JSON.parse(body);

	// was captcha successful?
        if(body.success !== undefined && !body.success){
            req.flash('danger', 'Failed captcha verification. Please try again.');
            return res.json({"success": false});
        }


	fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nLOGIN_EMAIL_SENT", (err) => {
	    if (err) throw err;
	});


                                var emailToken = jwt.sign(
                                    {
                                        email: email
                                    },
                                    EMAIL_SECRET,
                                    {
                                        expiresIn: 300, // 1 day = 86400 seconds, 5 minutes = 300 seconds
                                    }
                                );

                                var loginURL = "https://"+DOMAIN_NAME+"/login/" + emailToken;

                                // create reusable transporter object using the default SMTP transport
                                let transporter = nodemailer.createTransport({
                                    host: 'smtp.gmail.com',
                                    port: 465,
                                    secure: true, // true for 465, false for other ports
                                    auth: {
                                        user: EMAIL_ADDRESS, // generated ethereal user
                                        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
                                    }
                                });

                                // setup email data with unicode symbols
                                let mailOptions = {
                                    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                                    to: email, // list of receivers
                                    bcc: EMAIL_ADDRESS, // list of receivers
                                    subject: 'friend of Geofree', // Subject line
                                    text: '', // plain text body
                                    html: 'Welcome 👋<br><br>To login, click the link below:<br><a target="_blank" href="' + loginURL + '">' + loginURL + '</a><br><br><span style="font-size:10px;">P.S. if the link expired, you can always get a new login link by re-entering your email at <a href="https://friendofgeofree.com/" target="_blank">friendofgeofree.com</a>.<br>Links expire 5 minutes after they\'re sent for security.</span><br><br>'
                                };


                                // send mail with defined transport object
                                transporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        return console.log(error);
                                    }
                                    //console.log('Message sent: %s', info.messageId);
                                    // Preview only available when sending through an Ethereal account
                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
                                });

                                return res.json({"success": true});

    });
});


// login route
app.get('/login/:token', isLoggedInMiddleware(), function (req, res) {
    try {
        var decoded = jwt.verify(req.params.token, EMAIL_SECRET);
	var email = decoded.email;


        // is this a new or returning user?
        neo4j_session
            .run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} RETURN u", { emailParam: email })
            .then(function (result) {
		
                if (result.records[0]._fields[0] == null) {
                        neo4j_session
                            .run("CREATE (u:User { email: {emailParam}, contact: '', addCount: 0, addFriendCount: 0, allSchools: true, currentIndex: false, matchIndex: false, statementQuery: '', latitude: 0, longitude: 0 })", { emailParam: email })
                            .then(function (result2) {
		                neo4j_session.close();
                            })
                            .catch(function (error) {
                                console.log(error);
                            });
                }
		                neo4j_session.close();
            })
            .catch(function (error) {
                console.log(error);
            });

                                // create reusable transporter object using the default SMTP transport
                                let transporter = nodemailer.createTransport({
                                    host: 'smtp.gmail.com',
                                    port: 465,
                                    secure: true, // true for 465, false for other ports
                                    auth: {
                                        user: EMAIL_ADDRESS, // generated ethereal user
                                        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
                                    }
                                });

                                // setup email data with unicode symbols
                                let mailOptions = {
                                    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                                    to: EMAIL_ADDRESS, // list of receivers
                                    subject: 'friend of Geofree', // Subject line
                                    text: '', // plain text body
                                    html: email + ' logged in'
                                };


                                // send mail with defined transport object
                                transporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        return console.log(error);
                                    }
                                    //console.log('Message sent: %s', info.messageId);
                                    // Preview only available when sending through an Ethereal account
                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
                                });



	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();

		fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nLOGIN", (err) => {
		    if (err) throw err;
		});

		req.login(email, function(err) {
		    res.redirect('/settings');
		});


    } catch (err) {
//	req.flash('danger', 'Your login expired, please re-verify.');
	res.send('Links expire 5 minutes after they\'re sent for security. Please <a href="/">go back</a> and re-enter your email address.');
    }
});




// Logout page
app.get('/logout', (req, res, next) => {
    // read the top comment by user SogMosee https://www.youtube.com/watch?v=mFVqL5aIjSE&list=PLpPnRKq7eNW3Qm2OfoJ3Hyvf-36TulLDp&index=8

let date_ob = new Date();
let date = ("0" + date_ob.getDate()).slice(-2);
let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
let year = date_ob.getFullYear();
let hours = date_ob.getHours();
let minutes = date_ob.getMinutes();
let seconds = date_ob.getSeconds();
fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+req.user+"\nLOGOUT", (err) => {
    if (err) throw err;
});


    req.logout();
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});




// delete my account
app.get('/delete-my-account', (req, res, next) => {

    var email = req.user;

let date_ob = new Date();
let date = ("0" + date_ob.getDate()).slice(-2);
let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
let year = date_ob.getFullYear();
let hours = date_ob.getHours();
let minutes = date_ob.getMinutes();
let seconds = date_ob.getSeconds();
fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nDELETE ACCOUNT", (err) => {
    if (err) throw err;
});


    req.logout();
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
    });

    neo4j_session
        .run("MATCH (u:User) WHERE u.email={emailParam} DETACH DELETE u", { emailParam: email})
        .then(function (result) {
            neo4j_session.close();
//            req.flash('danger', 'Your account has been removed from the database.');
            res.send('Your account has been deleted.');
        })
        .catch(function (error) {
            console.log(error);
        });

});




// Search Add Tag Route
app.get('/search/add_tag', authenticationMiddleware(), function (req, res) {
    res.redirect('/commonalities');
});
app.post('/search/add_tag', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var tag = req.body.tag.trim();
    var isUpload = req.body.isUpload;
    var weight = parseInt(req.body.weight);

    if (isUpload) {
	weight = 1;
    }

    if (tag === "") {
        req.flash('warning', 'You didn\'t type any text.');
        res.redirect('/commonalities');
    } else if (tag.length > 100) {
	res.send('Exceeds 100 characters. Please try again.');
    } else if (weight > 100 || weight < -100) {
	res.send('error');
    } else {

    neo4j_session
        .run("MATCH (u:User) WHERE u.email={emailParam} SET u.addCount = u.addCount+1 RETURN u.addCount", { emailParam: email})
        .then(function (result) {
            var addCount = result.records[0]._fields[0].low;
            if (addCount > MAX_ADD_COUNT) {


				let date_ob = new Date();
				let date = ("0" + date_ob.getDate()).slice(-2);
				let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
				let year = date_ob.getFullYear();
				let hours = date_ob.getHours();
				let minutes = date_ob.getMinutes();
				let seconds = date_ob.getSeconds();
				fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nCOMMONALITY_LIMIT_EXCEEDED", (err) => {
				    if (err) throw err;
				});

		/*
                                // create reusable transporter object using the default SMTP transport
                                let transporter = nodemailer.createTransport({
                                    host: 'smtp.gmail.com',
                                    port: 465,
                                    secure: true, // true for 465, false for other ports
                                    auth: {
                                        user: EMAIL_ADDRESS, // generated ethereal user
                                        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
                                    }
                                });

                                // setup email data with unicode symbols
                                let mailOptions = {
                                    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                                    to: EMAIL_ADDRESS, // list of receivers
                                    subject: email + ' went over the add info limit.', // Subject line
                                    text: '', // plain text body
                                    html: email
                                };

                                // send mail with defined transport object
                                transporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        return console.log(error);
                                    }
                                    //console.log('Message sent: %s', info.messageId);
                                    // Preview only available when sending through an Ethereal account
                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
                                });
		*/


                neo4j_session.close();
		req.flash('danger', 'Daily limit exceeded. Please wait 24hrs before you add any more commonalities.');
//                res.send('Daily limit exceeded. Please wait 24hrs before you add any more commonalities.');
                res.redirect('/commonalities');
            }
            else {

		    neo4j_session
        		.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} SET u.statementQuery = {tagParam} RETURN COUNT(r)", { emailParam: email, tagParam: tag })
	        	.then(function(result9){

				var isThisSomethingTheUserAlreadyAdded = result9.records[0]._fields[0].low;

				if (isThisSomethingTheUserAlreadyAdded == 0) {


			                neo4j_session
			                    .run("MATCH (u:User) WHERE u.email={emailParam} MERGE (t:Tag {description:{tagParam}}) MERGE (u)-[:HAS {weight: {weightParam}}]->(t)", { emailParam: email, tagParam: tag, weightParam: weight })
			                    .then(function (result2) {

						let date_ob = new Date();
						let date = ("0" + date_ob.getDate()).slice(-2);
						let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
						let year = date_ob.getFullYear();
						let hours = date_ob.getHours();
						let minutes = date_ob.getMinutes();
						let seconds = date_ob.getSeconds();
						fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nADDED_COMMONALITY\n"+tag+"\n"+weight, (err) => {
						    if (err) throw err;
						});

				                neo4j_session
        	        			    .run("MATCH (u:User) WHERE u.email={emailParam} SET u.currentIndex = {tagParam}", { emailParam: email, tagParam: tag })
			                	    .then(function (result3) {

							if (isUpload) {
						                neo4j_session
	        					            .run("MATCH (u:User) WHERE u.email={emailParam} SET u.statementQuery = {tagParam}", { emailParam: email, tagParam: tag })
			                	    		    .then(function (result4) {
	        				       		        neo4j_session.close();
									res.redirect('/commonalities');
//									res.redirect('/commonalities#'+tag);
						                    })
        						            .catch(function (error) {
        	        		        			console.log(error);
			                			    });
							} else {
			        	       		        neo4j_session.close();
								res.redirect('/commonalities');
							}

				                    })
        	        			    .catch(function (error) {
			                	        console.log(error);
                				    });

			                    })
			                    .catch(function (error) {
                        			console.log(error);
			                    });
				} else {
			        	       		        neo4j_session.close();
								req.flash('warning', 'You already added this commonality.');
								res.redirect('/commonalities');
//								res.redirect('/commonalities#'+tag);
				}
			})
       			.catch(function (error) {
		            console.log(error);
       			});
            }
        })
        .catch(function (error) {
            console.log(error);
        });
    }
});







// Search Remove Tag Route
app.get('/search/remove_tag', authenticationMiddleware(), function (req, res) {
    res.redirect('/commonalities');
});
app.post('/search/remove_tag', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var tag = req.body.tag;

//https://usefulangle.com/post/187/nodejs-get-date-time

let date_ob = new Date();
let date = ("0" + date_ob.getDate()).slice(-2);
let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
let year = date_ob.getFullYear();
let hours = date_ob.getHours();
let minutes = date_ob.getMinutes();
let seconds = date_ob.getSeconds();
fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nREMOVED_COMMONALITY\n"+tag, (err) => {
    if (err) throw err;
});


neo4j_session
    .run("MATCH(u:User) WHERE u.email={emailParam} RETURN u.allSchools", {emailParam: email})
    .then(function (result) {
	var allSchools = result.records[0]._fields[0];


    neo4j_session
        .run("MATCH (u:User)-[r:HAS]->(t:Tag {description: {tagParam}}) WHERE u.email={emailParam} DELETE r", { tagParam: tag, emailParam: email })
        .then(function (result1) {


if (allSchools) {

	    neo4j_session
	        .run("MATCH(t:Tag)-[r]-() WHERE t.description={tagParam} RETURN COUNT(r)", {tagParam: tag})
        	.then(function (result2) {

	            var relationshipCount = result2.records[0]._fields[0].low;


		    if (relationshipCount == 0) {
			    neo4j_session
			        .run("MATCH(u:User) WHERE u.email={emailParam} SET u.currentIndex = false", {emailParam: email})
        			.then(function (result3) {

		        	    neo4j_session.close();
        			    res.redirect('/commonalities');

			        })
        			.catch(function (error) {
        			    console.log(error);
        			});
		    } else {
			    neo4j_session
			        .run("MATCH (u:User) WHERE u.email={emailParam} SET u.currentIndex={tagParam}", { emailParam: email, tagParam: tag })
        			.then(function (result4) {

		        	    neo4j_session.close();
//				    req.flash('danger', 'are you a Peeping Tom?');
        			    res.redirect('/commonalities');

			        })
        			.catch(function (error) {
        			    console.log(error);
        			});
		    }
	        })
        	.catch(function (error) {
        	    console.log(error);
        	});
} else {
	    neo4j_session
	        .run("MATCH(t:Tag)-[r:HAS]-(u:User) WHERE t.description={tagParam} AND u.email ENDS WITH {emailDomainParam} RETURN COUNT(r)", {tagParam: tag, emailDomainParam: email.substring(email.indexOf('@'))})
        	.then(function (result5) {

	            var relationshipCount = result5.records[0]._fields[0].low;


		    if (relationshipCount == 0) {
			    neo4j_session
			        .run("MATCH(u:User) WHERE u.email={emailParam} SET u.currentIndex = false", {emailParam: email})
        			.then(function (result6) {

		        	    neo4j_session.close();
        			    res.redirect('/commonalities');

			        })
        			.catch(function (error) {
        			    console.log(error);
        			});
		    } else {
			    neo4j_session
			        .run("MATCH (u:User) WHERE u.email={emailParam} SET u.currentIndex={tagParam}", { emailParam: email, tagParam: tag })
        			.then(function (result7) {

		        	    neo4j_session.close();
//				    req.flash('danger', 'are you a Peeping Tom?');
        			    res.redirect('/commonalities');

			        })
        			.catch(function (error) {
        			    console.log(error);
        			});
		    }
	        })
        	.catch(function (error) {
        	    console.log(error);
        	});
}

        })
        .catch(function (error) {
            console.log(error);
        });
    })
    .catch(function (error) {
	console.log(error);
    });
});


/*
// All Schools Route
app.get('/play/all_schools', authenticationMiddleware(), function (req, res) {
    res.redirect('/play');
});
app.post('/play/all_schools', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var allSchools = (req.body.allSchools == 'true'); // https://stackoverflow.com/questions/263965/how-can-i-convert-a-string-to-boolean-in-javascript


let date_ob = new Date();
let date = ("0" + date_ob.getDate()).slice(-2);
let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
let year = date_ob.getFullYear();
let hours = date_ob.getHours();
let minutes = date_ob.getMinutes();
let seconds = date_ob.getSeconds();
fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nALL_SCHOOLS\n"+allSchools, (err) => {
    if (err) throw err;
});


    neo4j_session
        .run("MATCH (u:User) WHERE u.email={emailParam} SET u.allSchools={allSchoolsParam}, u.currentIndex=false, u.statementQuery=''", { emailParam: email, allSchoolsParam: allSchools })
        .then(function (result) {
            neo4j_session.close();
            res.redirect('/play');
        })
        .catch(function (error) {
            console.log(error);
        });
});
*/


// Search Query Route
app.get('/search/query', authenticationMiddleware(), function (req, res) {
    res.redirect('/commonalities');
});
app.post('/search/query', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var statementQuery = req.body.statementQuery.toLowerCase().trim();

    if (statementQuery.length > 100) {
	req.flash('danger', 'Exceeds 100 characters. Please try again.');
	res.redirect('/commonalities');
    }


    neo4j_session
        .run("MATCH (u:User) WHERE u.email={emailParam} SET u.statementQuery={statementQueryParam}, u.currentIndex=false", { emailParam: email, statementQueryParam: statementQuery })
        .then(function (result) {
            neo4j_session.close();
            res.redirect('/commonalities');
        })
        .catch(function (error) {
            console.log(error);
        });



});








// matches Route
app.get('/matches', authenticationMiddleware(), function (req, res) {
    var email = req.user;


                    neo4j_session
                        .run("OPTIONAL MATCH (u:User) WHERE u.email={emailParam} RETURN u.matchIndex, u.latitude, u.longitude", {emailParam: email})
                        .then(function (result6) {
		            var matchIndex = result6.records[0]._fields[0];
		            var latitude = result6.records[0]._fields[1];
        		    var longitude = result6.records[0]._fields[2];


                    neo4j_session
                        .run("OPTIONAL MATCH (u:User)-[r]-(v:User) WHERE u.email={emailParam} RETURN ID(v), startnode(r).email, type(r), v.contact", {emailParam: email})
                        .then(function (result5) {
                            var relationshipsArr = [];

                            result5.records.forEach(function (record) {
                                if (record._fields[0] != null) {
                                    relationshipsArr.push({ email: record._fields[0].low, startNode: record._fields[1], relationshipType: record._fields[2], contact: record._fields[3] });
                                }
                            });


                    neo4j_session
                        .run("OPTIONAL MATCH (u:User)-[r1:HAS]-(commonTag:Tag)-[r2:HAS]-(kindredSpirit:User) WHERE u.email={emailParam} RETURN ID(kindredSpirit), commonTag.description, toInt(r1.weight), toInt(r2.weight), kindredSpirit.latitude, kindredSpirit.longitude ORDER BY ID(kindredSpirit)", {emailParam: email})
                        .then(function (result4) {
                            var unsortedKindredArr = [];

                            result4.records.forEach(function (record) {
                                if (record._fields[0] != null) {
                                    unsortedKindredArr.push({ email: record._fields[0].low, tag: record._fields[1], weight1: record._fields[2].low, weight2: record._fields[3].low, latitude: record._fields[4], longitude: record._fields[5] });
                                }
                            });

                            // https://stackoverflow.com/questions/53308478/parse-data-into-json
                            var sortedKindredArr = unsortedKindredArr.reduce((all, record) => {
                                var user = all.find(u => u.email === record.email);

				var affinityValue = 0;
				if (record.weight1 > -1 && record.weight2 > -1) {
				    affinityValue = Math.min(record.weight1, record.weight2);
				} else if (record.weight1 < 0 && record.weight2 < 0) {
				    affinityValue = Math.abs(Math.max(record.weight1, record.weight2));
				} else {
				    affinityValue = -Math.abs(record.weight1 - record.weight2);
				}

				var isSwipe = false;
				var isMatch = false;
				var matchContactInfo = "";
				relationshipsArr.forEach( function(relationship) {
					if (record.email == relationship.email) {
						if (email.localeCompare(relationship.startNode) == 0 && "SWIPE".localeCompare(relationship.relationshipType) == 0) {
							isSwipe = true;
							//break;
						} else if ("MATCH".localeCompare(relationship.relationshipType) == 0) {
							isMatch = true;
							matchContactInfo = relationship.contact;
							//break;
						}
						//break;
					}
				});


                                //If already exists person now contains existing person
                                if (user) {
                                    user.tags.push([record.tag, record.weight1, record.weight2, affinityValue]);
                                    user.weightSum += affinityValue;
                                    //add new interest
                                } else all.push({
                                    email: record.email,
                                    tags: [[record.tag, record.weight1, record.weight2, affinityValue]],
				    weightSum: affinityValue,
				    isSwipe: isSwipe,
				    isMatch: isMatch,
				    contactInfo: matchContactInfo,
				    distance: distance(latitude, record.latitude, longitude, record.longitude)

                                    //creates new person object
                                });

                                return all;
                            }, []).sort((a, b) => b.weightSum - a.weightSum);
                            //sorts based on length of interest array


				neo4j_session.close();

				res.render('matches', {
				    kindred: sortedKindredArr,
				    //testtest: relationshipsArr,
				    matchIndex: matchIndex
				});

			})
			.catch(function (error) {
			    console.log(error);
			});

			})
			.catch(function (error) {
			    console.log(error);
			});

			})
			.catch(function (error) {
			    console.log(error);
			});
});




// commonalities Route
app.get('/commonalities', authenticationMiddleware(), function (req, res) {
    var email = req.user;

    neo4j_session
        .run("OPTIONAL MATCH (u:User)-[r1:HAS]-(commonTag:Tag)-[r2:HAS]-(kindredSpirit:User) WHERE u.email={emailParam} RETURN COUNT(DISTINCT kindredSpirit)", {emailParam: email})
        .then(function(result0){
            var kindredSpiritCount = result0.records[0]._fields[0].low;


    neo4j_session
        .run("MATCH(u:User) WHERE u.email={emailParam} RETURN u.addCount, u.allSchools, u.currentIndex, u.statementQuery", {emailParam: email})
        .then(function(result){
            var addCount = result.records[0]._fields[0].low;
            var allSchools = result.records[0]._fields[1];
            var currentIndex = result.records[0]._fields[2];
            var statementQuery = result.records[0]._fields[3];


	    if (statementQuery === "") {

	                            neo4j_session.close();

	                            res.render('commonalities', {
					query: "",
					statementIndex: currentIndex,
	                                searchAllSchools: allSchools,
	                                tags: [],
                	                tagsAll: [],
					searchCount: 0,
					kindredSpiritCount: kindredSpiritCount
                        	    });

	    }
	    else {

            neo4j_session
                .run("OPTIONAL MATCH (u:User)-[r:HAS]->(t:Tag) WHERE u.email={emailParam} RETURN t.description, toInt(r.weight) ORDER BY r.weight DESC", {emailParam: email})
                .then(function(result2){
                    var tagArr = [];

                    result2.records.forEach(function (record) {
                        if (record._fields[0] != null) {
                            tagArr.push({ description: record._fields[0], weight: record._fields[1].low });
                        }
                    });


			    neo4j_session
			        .run("MATCH (u:User)-[r:HAS]->(t:Tag) WHERE toLower(t.description) CONTAINS toLower({statementQueryParam}) RETURN t, COUNT(r), t.description ORDER BY toUpper(t.description) LIMIT 20", {statementQueryParam: statementQuery})
//			        .run("MATCH (u:User)-[r:HAS]->(t:Tag) RETURN t, COUNT(r), t.description ORDER BY toUpper(t.description)")
//			        .run("MATCH (u:User)-[r:HAS]->(t:Tag) RETURN DISTINCT t.description ORDER BY toUpper(t.description)")
			        .then(function (result4) {
			            var tagArrAll = [];
			            result4.records.forEach(function (record) {
			                tagArrAll.push({
//			                    description: record._fields[0]
			                    description: record._fields[0].properties.description,
			                    count: record._fields[1].low
			                });
			            });
 

			                            neo4j_session.close();

		        	                    res.render('commonalities', {
							query: statementQuery,
							statementIndex: currentIndex,
		                	       	        searchAllSchools: allSchools,
		                        	        tags: tagArr,
                		                	tagsAll: tagArrAll,
							kindredSpiritCount: kindredSpiritCount
        	                		    });
			        })
			        .catch(function (error) {
        			    console.log(error);
			        });
		})
		.catch(function (error) {
		    console.log(error);
                });
	    }
	})
	.catch(function (error) {
	    console.log(error);
        });
	})
	.catch(function (error) {
	    console.log(error);
        });
});



/*
// view all commonalities route
app.get('/commonalities', authenticationMiddleware(), function (req, res) {
    var email = req.user;

    neo4j_session
        .run("MATCH (:User)-[r:HAS]->(t:Tag) RETURN t.description, COUNT(r) ORDER BY toUpper(t.description)")
        .then(function (result4) {
            var tagArrAll = [];
            result4.records.forEach(function (record) {
                tagArrAll.push({
                    description: record._fields[0],
                    count: record._fields[1].low
                });
            });

            neo4j_session
                .run("OPTIONAL MATCH (u:User)-[r:HAS]->(t:Tag) WHERE u.email={emailParam} RETURN t.description, toInt(r.weight) ORDER BY r.weight DESC", {emailParam: email})
                .then(function(result2){
                    var tagArr = [];

                    result2.records.forEach(function (record) {
                        if (record._fields[0] != null) {
                            tagArr.push({ description: record._fields[0], weight: record._fields[1].low });
                        }
                    });

 
	                            neo4j_session.close();

		                    res.render('commonalities', {
     	        		        tagsAll: tagArrAll,
	                                tags: tagArr
                        	    });


		})
		.catch(function (error) {
		    console.log(error);
                });
	})
	.catch(function (error) {
	    console.log(error);
        });
});
*/


// settings Route
app.get('/settings', authenticationMiddleware(), function (req, res) {
    var email = req.user;

    neo4j_session
        .run("MATCH(u:User) WHERE u.email={emailParam} RETURN u.contact, u.latitude, u.longitude", {emailParam: email})
        .then(function(result){
            var contact = result.records[0]._fields[0];
            var latitude = result.records[0]._fields[1];
            var longitude = result.records[0]._fields[2];

if (contact === "") {
	                            neo4j_session.close();

	                            res.render('settings', {
	                                tags: [],
					user: email,
					contactInfo: contact,
					latitude: latitude,
					longitude: longitude
                        	    });
} else {
            neo4j_session
                .run("OPTIONAL MATCH (u:User)-[r:HAS]->(t:Tag) WHERE u.email={emailParam} RETURN t.description, toInt(r.weight) ORDER BY r.weight DESC", {emailParam: email})
                .then(function(result2){
                    var tagArr = [];

                    result2.records.forEach(function (record) {
                        if (record._fields[0] != null) {
                            tagArr.push({ description: record._fields[0], weight: record._fields[1].low });
                        }
                    });

 
	                            neo4j_session.close();

	                            res.render('settings', {
	                                tags: tagArr,
					user: email,
					contactInfo: contact,
					latitude: latitude,
					longitude: longitude
                        	    });


		})
		.catch(function (error) {
		    console.log(error);
                });
}
	})
	.catch(function (error) {
	    console.log(error);
        });
});





// Change Value Route
app.get('/change-value', authenticationMiddleware(), function (req, res) {
    res.redirect('/commonalities');
});
app.post('/change-value', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var tag = req.body.tag;
    var weight = parseInt(req.body.weight);

    if ((weight > 100 || weight < -100) || tag.length > 100) {
	res.send('error');
    } else {

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();


	if (weight == 0) {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nREMOVE_COMMONALITY\n"+tag, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} DELETE r", { emailParam: email, tagParam: tag })
	        .then(function(result){

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE t.description={tagParam} RETURN COUNT(r)", { emailParam: email, tagParam: tag })
	        .then(function(result2){

		var isNodeConnected = result2.records[0]._fields[0].low;

			if (isNodeConnected == 0) {

			    neo4j_session
        			.run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} SET u.currentIndex=false", { emailParam: email })
	        		.then(function(result3){
					neo4j_session.close();
		                	res.redirect('/commonalities');
			        })
        			.catch(function (error) {
		        	    console.log(error);
		        	});

			} else {
					neo4j_session.close();
		                	res.redirect('/commonalities');
			}

			        })
        			.catch(function (error) {
			            console.log(error);
        			});
			        })
        			.catch(function (error) {
			            console.log(error);
        			});

	} else {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nCHANGE_WEIGHT\n"+tag+"\n"+weight, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
		.run("MATCH (u:User), (t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} SET u.currentIndex={tagParam} MERGE (u)-[r:HAS]->(t) ON CREATE SET r.weight={weightParam} ON MATCH SET r.weight={weightParam}", { emailParam: email, tagParam: tag, weightParam: weight })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/commonalities');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});
	}
    }
});






// Change Value All Route
app.get('/change-value-all', authenticationMiddleware(), function (req, res) {
    res.redirect('/database');
});
app.post('/change-value-all', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var tag = req.body.tag;
    var weight = parseInt(req.body.weight);

    if ((weight > 100 || weight < -100) || tag.length > 100) {
	res.send('error');
    } else {

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();


	if (weight == 0) {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nREMOVE_COMMONALITY\n"+tag, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} DELETE r", { emailParam: email, tagParam: tag })
	        .then(function(result){

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE t.description={tagParam} RETURN COUNT(r)", { emailParam: email, tagParam: tag })
	        .then(function(result2){

		var isNodeConnected = result2.records[0]._fields[0].low;

			if (isNodeConnected == 0) {

			    neo4j_session
        			.run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} SET u.currentIndex=false", { emailParam: email })
	        		.then(function(result3){
					neo4j_session.close();
		                	res.redirect('/database');
			        })
        			.catch(function (error) {
		        	    console.log(error);
		        	});

			} else {
					neo4j_session.close();
		                	res.redirect('/database');
			}

			        })
        			.catch(function (error) {
			            console.log(error);
        			});
			        })
        			.catch(function (error) {
			            console.log(error);
        			});

	} else {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nCHANGE_WEIGHT\n"+tag+"\n"+weight, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
		.run("MATCH (u:User), (t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} SET u.currentIndex={tagParam} MERGE (u)-[r:HAS]->(t) ON CREATE SET r.weight={weightParam} ON MATCH SET r.weight={weightParam}", { emailParam: email, tagParam: tag, weightParam: weight })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/database');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});
	}
    }
});






// Change Value settings Route
app.get('/change-value-settings', authenticationMiddleware(), function (req, res) {
    res.redirect('/settings');
});
app.post('/change-value-settings', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var tag = req.body.tag;
    var weight = parseInt(req.body.weight);

    if ((weight > 100 || weight < -100) || tag.length > 100) {
	res.send('error');
    } else {

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();


	if (weight == 0) {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nREMOVE_COMMONALITY\n"+tag, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} DELETE r", { emailParam: email, tagParam: tag })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/settings');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});

	} else {

	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nCHANGE_WEIGHT\n"+tag+"\n"+weight, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User)-[r:HAS]-(t:Tag) WHERE u.email={emailParam} AND t.description={tagParam} SET r.weight={weightParam}", { emailParam: email, tagParam: tag, weightParam: weight })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/settings');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});
	}
    }
});






// Update Contact Info Route
app.get('/update-contact-info', authenticationMiddleware(), function (req, res) {
    res.redirect('/settings');
});
app.post('/update-contact-info', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var contactInfo = req.body.contact;

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();


	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nUPDATE_CONTACT_INFO\n"+contactInfo, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} SET u.contact={contactParam}", { emailParam: email, contactParam: contactInfo })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/settings');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});
});






// Update Location Route
app.get('/update-location', authenticationMiddleware(), function (req, res) {
    res.redirect('/settings');
});
app.post('/update-location', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var latitude = parseFloat(req.body.latitude);
    var longitude = parseFloat(req.body.longitude);

    if ((latitude > 90 || latitude < -90) || (longitude > 180 || longitude < -180)) {
	res.send('error');
    }

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();


	    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nUPDATE_LOCATION\n"+latitude+"\n"+longitude, (err) => {
	        if (err) throw err;
	    });

	    neo4j_session
        	.run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} SET u.latitude={latitudeParam}, u.longitude={longitudeParam}", { emailParam: email, latitudeParam: latitude, longitudeParam: longitude })
	        .then(function(result){
			neo4j_session.close();
                	res.redirect('/settings');
	        })
        	.catch(function (error) {
	            console.log(error);
        	});
});






// Match Swipe Route
app.get('/match/swipe', authenticationMiddleware(), function (req, res) {
    res.redirect('/matches');
});
app.post('/match/swipe', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var matchId = parseInt(req.body.matchId);

    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours();
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();

    neo4j_session
        .run("MATCH(u:User) WHERE u.email={emailParam} SET u.addFriendCount=u.addFriendCount+1, u.matchIndex={matchIdParam} RETURN u.addFriendCount, u.contact, ID(u)", { emailParam: email, matchIdParam: matchId })
        .then(function(result){
            var addFriendCount = result.records[0]._fields[0].low;
            var contactInfo = result.records[0]._fields[1];
            var theirId = result.records[0]._fields[2].low;

	    if (contactInfo === "") {

		neo4j_session.close();
		req.flash('danger', 'Please fill out your contact info.');
                res.redirect('/settings');

	    } else if (addFriendCount > MAX_SWIPE_COUNT) {

		fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nSWIPE_LIMIT_EXCEEDED", (err) => {
		    if (err) throw err;
		});


		neo4j_session.close();
		req.flash('danger', 'Daily limit exceeded. Please wait 24hrs before you like any more.');
//                res.send('Daily limit exceeded. Please wait until 11am PST before you swipe any more.');
                res.redirect('/matches');
	    } else if (theirId == matchId) {
		fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nHACKER_TRIED_TO_SWIPE_RIGHT_ON_THEMSELF", (err) => {
		    if (err) throw err;
		});

		neo4j_session.close();
		req.flash('danger', 'Hmm...');
                res.redirect('/matches');
	    } else {

		neo4j_session
		    .run("OPTIONAL MATCH (u:User), (v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} RETURN u.latitude, v.latitude, u.longitude, v.longitude", { emailParam: email, matchIdParam: matchId })
		    .then(function (result999) {
		    	var yourLatitude = result999.records[0]._fields[0];
			var matchLatitude = result999.records[0]._fields[1];
			var yourLongitude = result999.records[0]._fields[2];
			var matchLongitude = result999.records[0]._fields[3];

			var distance123 = distance(yourLatitude, matchLatitude, yourLongitude, matchLongitude);
			if (distance123 == 99999) {
				distance123 = "n/a";
			} else {
				distance123 = distance123 + " miles";
			}

		neo4j_session
		    .run("OPTIONAL MATCH (u:User)-[r1:HAS]-(commonTag:Tag)-[r2:HAS]-(v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} RETURN commonTag.description, toInteger(r1.weight), toInteger(r2.weight)", {emailParam: email, matchIdParam: matchId })
		    .then(function (result5) {

		    	var commonTags = [];

			result5.records.forEach(function (record) {
                            if (record._fields[0] != null) {

				var affinityValue = 0;

				if (record._fields[1].low > -1 && record._fields[2].low > -1) {
				    affinityValue = Math.min(record._fields[1].low, record._fields[2].low);
				} else if (record._fields[1].low < 0 && record._fields[2].low < 0) {
				    affinityValue = Math.abs(Math.max(record._fields[1].low, record._fields[2].low));
				} else {
				    affinityValue = -Math.abs(record._fields[1].low - record._fields[2].low);
				}

                                commonTags.push({ description: record._fields[0], weight1: record._fields[1].low, weight2: record._fields[2].low, affinity: affinityValue });
			    }
                        });

			commonTags.sort((a, b) => b['affinity'] - a['affinity']);


			var commonTagsHistoryTxtString = '';
		        var commonTagsEmailString = '';

			commonTags.forEach(function (tag) {
			    commonTagsHistoryTxtString = commonTagsHistoryTxtString + "\n" + tag.description + "\n" + tag.weight1 + ", " + tag.weight2;
			    commonTagsEmailString = commonTagsEmailString + "<br>&nbsp;&nbsp;&nbsp;&nbsp;&bull;&nbsp;&nbsp;" + tag.description + "&nbsp;&nbsp;&nbsp;(" + tag.weight2 + ", " + tag.weight1 + ")";
			});



		    neo4j_session
		        .run("OPTIONAL MATCH (u:User)<-[r:SWIPE]-(v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} RETURN r IS NOT NULL", { emailParam: email, matchIdParam: matchId })
		        .then(function (result2) {

				var friendRequestEdgeCase = result2.records[0]._fields[0];

				if (friendRequestEdgeCase) {


				    neo4j_session
					.run("OPTIONAL MATCH (u:User)<-[r:SWIPE]-(v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} DELETE r", { emailParam: email, matchIdParam: matchId })
				        .then(function (result3) {

				    neo4j_session
				        .run("OPTIONAL MATCH (u:User), (v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} SET u.matchIndex={matchIdParam} MERGE (u)-[:MATCH]-(v) RETURN v.email, v.contact, u.contact", { emailParam: email, matchIdParam: matchId })
				        .then(function (result4) {
					    var matchEmail = result4.records[0]._fields[0];
					    var matchContact = result4.records[0]._fields[1];
					    var yourContact = result4.records[0]._fields[2];


						fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\n"+matchEmail+"\nMATCHED\n"+yourContact+"\n"+matchContact+"\n"+distance123+commonTagsHistoryTxtString, (err) => {
						    if (err) throw err;
						});


		                                // create reusable transporter object using the default SMTP transport
                		                let transporter = nodemailer.createTransport({
		                                    host: 'smtp.gmail.com',
                		                    port: 465,
                                		    secure: true, // true for 465, false for other ports
		                                    auth: {
                		                        user: EMAIL_ADDRESS, // generated ethereal user
                                		        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
		                                    }
                		                });

		                                // setup email data with unicode symbols
                		                let mailOptions = {
                                		    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                		                    bcc: [matchEmail, email, EMAIL_ADDRESS], // list of receivers
                                		    subject: 'You both swiped right!', // Subject line
		                                    text: '', // plain text body
                		                    html: 

							'Congratulations.<br>' + 
							'<br>' +
							'Here\'s your distance: <br>' + 
							'&nbsp;&nbsp;&nbsp;&nbsp;&bull;&nbsp;&nbsp;' + distance123 + '<br>' + 
							'<br>' +
							'Here\'s your contact infos: <br>' + 
							'&nbsp;&nbsp;&nbsp;&nbsp;&bull;&nbsp;&nbsp;' + matchContact + '<br>' + 
							'&nbsp;&nbsp;&nbsp;&nbsp;&bull;&nbsp;&nbsp;' + yourContact + '<br>' + 
							'<br>' +
							'Here\'s your commonalities and values:' +
							commonTagsEmailString + '<br>' + 
							'<br>' + 
							'Thanks for using <a href="https://friendofgeofree.com/" target="_blank">friendofgeofree.com</a> 🙂<br>' + 
							'<br>'
							// + '[Your Ad Here]<br><br>' 
 		                               };

                		                // send mail with defined transport object
		                                transporter.sendMail(mailOptions, (error, info) => {
                		                    if (error) {
                                		        return console.log(error);
		                                    }
                		                    //console.log('Message sent: %s', info.messageId);
                                		    // Preview only available when sending through an Ethereal account
		                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                		                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                		    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
		                                });




		    			    neo4j_session.close();
					    //req.flash('success', 'Check your email, it\'s a match!');
  				            res.redirect('/matches');
  				        })
 				        .catch(function (error) {
					    console.log(error);
	 			        });
  					})
 					.catch(function (error) {
				    	console.log(error);
		 			});
				} else {
				    neo4j_session
				        .run("OPTIONAL MATCH (u:User), (v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} MERGE (u)-[:SWIPE]->(v) RETURN v.email", { emailParam: email, matchIdParam: matchId })
				        .then(function (result3) {
					   var matchEmail = result3.records[0]._fields;


						fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nSWIPE\n"+matchEmail+"\n"+distance123+commonTagsHistoryTxtString, (err) => {
						    if (err) throw err;
						});


		    			   neo4j_session.close();
					   //req.flash('warning', 'If they swipe right on you later, I\'ll let you know via email.');
  				           res.redirect('/matches');
  				      })
 				       .catch(function (error) {
					   console.log(error);
	 			      });
				}
  		      })
 		      .catch(function (error) {
 		          console.log(error);
 		      });

  		      })
 		      .catch(function (error) {
 		          console.log(error);
 		      });

  		      })
 		      .catch(function (error) {
 		          console.log(error);
 		      });
	    }
        })
        .catch(function (error) {
            console.log(error);
        });
});



// Match Undo Route
app.get('/match/undo', authenticationMiddleware(), function (req, res) {
    res.redirect('/matches');
});
app.post('/match/undo', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var matchId = parseInt(req.body.matchId);
    var matchEmail = "";
    var matchType = "";

    neo4j_session
        .run("OPTIONAL MATCH (u:User)-[r]-(v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} RETURN v.email, type(r)", { emailParam: email, matchIdParam: matchId })
        .then(function (result) {

	    matchEmail = result.records[0]._fields[0];
	    matchType = result.records[0]._fields[1];


    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours();
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();

    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nUNDO "+matchType+"\n"+matchEmail, (err) => {
        if (err) throw err;
    });

    neo4j_session
        .run("OPTIONAL MATCH (u:User)-[r]-(v:User) WHERE u.email={emailParam} AND ID(v)={matchIdParam} SET u.matchIndex={matchIdParam} DELETE r", { emailParam: email, matchIdParam: matchId })
        .then(function (result2) {

	    neo4j_session.close();
            res.redirect('/matches');

	})
	.catch(function (error) {
	    console.log(error);
	});

	})
	.catch(function (error) {
	    console.log(error);
	});
});



// Icebreaker Route
app.get('/icebreaker', authenticationMiddleware(), function (req, res) {
	                            res.render('icebreaker', {
					user: req.user
                        	    });
});
app.post('/icebreaker', authenticationMiddleware(), function (req, res) {
    var email = req.user;
    var friendRequestEmail = req.body.email.toLowerCase().trim();

    let date_ob = new Date();
    let date = ("0" + date_ob.getDate()).slice(-2);
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    let year = date_ob.getFullYear();
    let hours = date_ob.getHours();
    let minutes = date_ob.getMinutes();
    let seconds = date_ob.getSeconds();

    if (email.localeCompare(friendRequestEmail) == 0) {
	    req.flash('danger', 'You can\'t send yourself an icebreaker request.');
            res.redirect('/icebreaker');
    } else {

    neo4j_session
        .run("OPTIONAL MATCH(u:User) WHERE u.email={emailParam} SET u.addFriendCount=u.addFriendCount+1 RETURN u.addFriendCount", { emailParam: email })
        .then(function(result){
            var addFriendCount = result.records[0]._fields[0].low;

	    if (addFriendCount > MAX_SWIPE_COUNT) {

		fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nSWIPE_LIMIT_EXCEEDED", (err) => {
		    if (err) throw err;
		});


		neo4j_session.close();
		req.flash('danger', 'Daily limit exceeded. Please wait 24hrs before you send any more icebreaker requests.');
//                res.send('Daily limit exceeded. Please wait until 11am PST before you swipe any more.');
                res.redirect('/icebreaker');
	    } else {

		neo4j_session
		    .run("OPTIONAL MATCH (v:User) WHERE v.email={emailParam} RETURN v.email", {emailParam: friendRequestEmail })
		    .then(function (result5) {

	                var doesFriendRequestEmailExist = result5.records[0]._fields[0];

				if (doesFriendRequestEmailExist != null) {

				     fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nICEBREAKER\n"+friendRequestEmail, (err) => {
				           if (err) throw err;
			             });

					neo4j_session
					    .run("OPTIONAL MATCH (u:User), (v:User) WHERE u.email={emailParam} AND v.email={email2Param} MERGE (u)-[:ICEBREAKER]->(v)", {emailParam: email, email2Param: friendRequestEmail })
					    .then(function (result6) {


                           	     var emailToken = jwt.sign(
                                	    {
                                        	email: email,
						friendRequestEmail: friendRequestEmail
        	                            },
                	                    EMAIL_SECRET,
                        	            {
                                	        expiresIn: 300, // 1 day = 86400 seconds, 5 minutes = 300 seconds
	                                    }
        	                        );

	                                var loginURL = "https://"+DOMAIN_NAME+"/accept/" + emailToken;

        	                        // create reusable transporter object using the default SMTP transport
                	                let transporter = nodemailer.createTransport({
                        	            host: 'smtp.gmail.com',
                                	    port: 465,
	                                    secure: true, // true for 465, false for other ports
        	                            auth: {
                	                        user: EMAIL_ADDRESS, // generated ethereal user
                        	                pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
                                	    }
	                                });

        	                        // setup email data with unicode symbols
                	                let mailOptions = {
                        	            from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                                	    to: friendRequestEmail, // list of receivers
	                                    bcc: EMAIL_ADDRESS, // list of receivers
        	                            subject: email + ' wants to break the ice', // Subject line
                	                    text: '', // plain text body
                        	            html: 'Click <a target="_blank" href="' + loginURL + '">here</a> to accept.<br><br><span style="font-size:10px;">P.S. if the link expired, they can always make a new request by re-entering your email at <a href="https://friendofgeofree.com/icebreaker" target="_blank">friendofgeofree.com</a>.<br>Links expire 5 minutes after they\'re sent for security.</span><br><br>'
                                	};


	                                // send mail with defined transport object
        	                        transporter.sendMail(mailOptions, (error, info) => {
                	                    if (error) {
                        	                return console.log(error);
                                	    }
	                                    //console.log('Message sent: %s', info.messageId);
        	                            // Preview only available when sending through an Ethereal account
                	                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                        	            // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                	    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
	                                });

		    			    neo4j_session.close();
			  		    })
 		      			    .catch(function (error) {
			 		        console.log(error);
			 		    });

				} else {
					    fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds+"\n"+email+"\nREQUEST_NONEXISTENT_USER\n"+friendRequestEmail, (err) => {
					        if (err) throw err;
					    });

		    			    neo4j_session.close();
				}

					    req.flash('warning', 'If they have an account, then your request was sent.');
  				            res.redirect('/icebreaker');
  		      })
 		      .catch(function (error) {
 		          console.log(error);
 		      });
	    }
        })
        .catch(function (error) {
            console.log(error);
        });
    }
});


// accept route
app.get('/accept/:token', function (req, res) {
    try {
        var decoded = jwt.verify(req.params.token, EMAIL_SECRET);
	var email = decoded.email;
	var friendRequestEmail = decoded.friendRequestEmail;


		neo4j_session
		    .run("OPTIONAL MATCH (u:User)-[r:ICEBREAKER]->(v:User) WHERE u.email={emailParam} AND v.email={email2Param} RETURN r IS NULL", {emailParam: email, email2Param: friendRequestEmail })
		    .then(function (result6) {

			var friendRequestAlreadyAccepted = result6.records[0]._fields[0];

			if (!friendRequestAlreadyAccepted) {

	let date_ob = new Date();
	let date = ("0" + date_ob.getDate()).slice(-2);
	let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
	let year = date_ob.getFullYear();
	let hours = date_ob.getHours();
	let minutes = date_ob.getMinutes();
	let seconds = date_ob.getSeconds();

				neo4j_session
				    .run("OPTIONAL MATCH (u:User)-[r:ICEBREAKER]->(v:User) WHERE u.email={emailParam} AND v.email={email2Param} DELETE r", {emailParam: email, email2Param: friendRequestEmail })
				    .then(function (result7) {

		neo4j_session
		    .run("OPTIONAL MATCH (u:User)-[r1:HAS]-(commonTag:Tag)-[r2:HAS]-(v:User) WHERE u.email={emailParam} AND v.email={email2Param} RETURN commonTag.description, toInteger(r1.weight), toInteger(r2.weight)", {emailParam: email, email2Param: friendRequestEmail })
		    .then(function (result5) {

		    	var commonTags = [];

			result5.records.forEach(function (record) {
                            if (record._fields[0] != null) {

				var affinityValue = 0;

				if (record._fields[1].low > -1 && record._fields[2].low > -1) {
				    affinityValue = Math.min(record._fields[1].low, record._fields[2].low);
				} else if (record._fields[1].low < 0 && record._fields[2].low < 0) {
				    affinityValue = Math.abs(Math.max(record._fields[1].low, record._fields[2].low));
				} else {
				    affinityValue = -Math.abs(record._fields[1].low - record._fields[2].low);
				}

                                commonTags.push({ description: record._fields[0], weight1: record._fields[1].low, weight2: record._fields[2].low, affinity: affinityValue });
			    }
                        });


			if (commonTags.length == 0) {

						fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds + "\n" + email + "\n" + friendRequestEmail + "\nICEBREAKER_REQUEST_ACCEPTED_BUT_NOTHING_IN_COMMON", (err) => {
						    if (err) throw err;
						});


		                                // create reusable transporter object using the default SMTP transport
                		                let transporter = nodemailer.createTransport({
		                                    host: 'smtp.gmail.com',
                		                    port: 465,
                                		    secure: true, // true for 465, false for other ports
		                                    auth: {
                		                        user: EMAIL_ADDRESS, // generated ethereal user
                                		        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
		                                    }
                		                });

		                                // setup email data with unicode symbols
                		                let mailOptions = {
                                		    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                		                    to: [email, friendRequestEmail], // list of receivers
		                                    bcc: EMAIL_ADDRESS, // list of receivers
                                		    subject: 'Well this is awkward...', // Subject line
		                                    text: '', // plain text body
                		                    html: 
							'According to my records, you two (currently) have nothing in common.'
 		                               };

                		                // send mail with defined transport object
		                                transporter.sendMail(mailOptions, (error, info) => {
                		                    if (error) {
                                		        return console.log(error);
		                                    }
                		                    //console.log('Message sent: %s', info.messageId);
                                		    // Preview only available when sending through an Ethereal account
		                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                		                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                		    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
		                                });
			} else {

			commonTags.sort((a, b) => b['affinity'] - a['affinity']);


			var commonTagsHistoryTxtString = '';
		        var commonTagsEmailString = '';

			commonTags.forEach(function (tag) {
			    commonTagsHistoryTxtString = commonTagsHistoryTxtString + "\n" + tag.description + "\n" + tag.weight1 + ", " + tag.weight2;
			    commonTagsEmailString = commonTagsEmailString + "<br>&nbsp;&nbsp;&nbsp;&nbsp;&bull;&nbsp;&nbsp;" + tag.description + "&nbsp;&nbsp;&nbsp;(" + tag.weight2 + ", " + tag.weight1 + ")";
			});

						fs.appendFile('history.txt', '\n\n'+year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds + "\n" + email + "\n" + friendRequestEmail + "\nICEBREAKER_REQUEST_ACCEPTED" + commonTagsHistoryTxtString, (err) => {
						    if (err) throw err;
						});


		                                // create reusable transporter object using the default SMTP transport
                		                let transporter = nodemailer.createTransport({
		                                    host: 'smtp.gmail.com',
                		                    port: 465,
                                		    secure: true, // true for 465, false for other ports
		                                    auth: {
                		                        user: EMAIL_ADDRESS, // generated ethereal user
                                		        pass: EMAIL_ADDRESS_PASSWORD // generated ethereal password
		                                    }
                		                });

		                                // setup email data with unicode symbols
                		                let mailOptions = {
                                		    from: '"Geofree Tze" <'+EMAIL_ADDRESS+'>', // sender address
                		                    to: [email, friendRequestEmail], // list of receivers
		                                    bcc: EMAIL_ADDRESS, // list of receivers
                                		    subject: 'Icebreaker Request accepted!', // Subject line
		                                    text: '', // plain text body
                		                    html: 
							'Here\'s your commonalities and values:' +
							commonTagsEmailString + '<br>' + 
							'<br>' + 
							'Thanks for using <a href="https://friendofgeofree.com/" target="_blank">friendofgeofree.com</a> 🙂<br>' + 
							'<br>' 
							// + '[Your Ad Here]<br><br>' 
 		                               };

                		                // send mail with defined transport object
		                                transporter.sendMail(mailOptions, (error, info) => {
                		                    if (error) {
                                		        return console.log(error);
		                                    }
                		                    //console.log('Message sent: %s', info.messageId);
                                		    // Preview only available when sending through an Ethereal account
		                                    //console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

                		                    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
                                		    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
		                                });
			}



		    			    neo4j_session.close();
					    res.send('Icebreaker request accepted! You should receive an email shortly.');
	            })
 		    .catch(function (error) {
		        console.log(error);
	 	    });
	            })
 		    .catch(function (error) {
		        console.log(error);
	 	    });
			} else {
		    			    neo4j_session.close();
					    res.send('Icebreaker request already accepted.');
			}
	            })
 		    .catch(function (error) {
		        console.log(error);
	 	    });
    } catch (err) {
//	req.flash('danger', 'Your login expired, please re-verify.');
	res.send('Sorry, the link expired. If you want to, you can ask them to send you another icebreaker request.');
    }
});



// database route
app.get('/database', authenticationMiddleware(), function (req, res) {

    neo4j_session
        .run("MATCH (:User)-[r:HAS]-(t:Tag) RETURN t.description, COUNT(r) ORDER BY toUpper(t.description)")
        .then(function (result4) {
            var tagArrAll = [];
            result4.records.forEach(function (record) {
                tagArrAll.push({
                    description: record._fields[0],
                    count: record._fields[1].low
                });
            });


	                            neo4j_session.close();

		                    res.render('database', {
     	        		        tagsAll: tagArrAll
                        	    });

	})
	.catch(function (error) {
	    console.log(error);
        });
});



app.listen(5000);

console.log('Server started on port 5000');

passport.serializeUser(function(email, done) {
    done(null, email);
});

passport.deserializeUser(function(email, done) {
    done(null, email);
});

function authenticationMiddleware() {
	return (req, res, next) => {

        if (req.isAuthenticated()) {
            return next();
        } else {
            res.redirect('/');
        }
	}
}

function isLoggedInMiddleware() {
	return (req, res, next) => {

        if (req.isAuthenticated()) {
            req.flash('warning', 'You\'re already logged in, so you were redirected to your settings page... if you want to view the homepage, please open an incognito tab or logout.');
            res.redirect('/settings');
        } else {
            return next();
        }
	}
}

function isAdmin() {
	return (req, res, next) => {

        if (req.user.localeCompare(EMAIL_ADDRESS) == 0) {
            return next();
        } else {
            res.redirect('/');
        }
	}
}

// https://www.geeksforgeeks.org/program-distance-two-points-earth/
function distance(lat1, lat2, lon1, lon2)
    {

if ((lat1 == 0 && lon1 == 0) || (lat2 == 0 && lon2 == 0)) {
        return 99999;
} else {
        lon1 =  lon1 * mathjs.pi / 180;
        lon2 = lon2 * mathjs.pi / 180;
        lat1 = lat1 * mathjs.pi / 180;
        lat2 = lat2 * mathjs.pi / 180;
   
        // Haversine formula
        let dlon = lon2 - lon1;
        let dlat = lat2 - lat1;
        let a = mathjs.pow(mathjs.sin(dlat / 2), 2)
                 + mathjs.cos(lat1) * mathjs.cos(lat2)
                 * mathjs.pow(mathjs.sin(dlon / 2), 2);
               
        let c = 2 * mathjs.asin(mathjs.sqrt(a));
   
        // Radius of earth in miles
        let r = 3956;
   
        // calculate the result
        return parseInt(c * r)+2;
}
    }

module.exports = app;
