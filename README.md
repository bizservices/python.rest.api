# Python REST API
## Building a REST API
When you decide that you need a rest api, there are a lot of (tough) choices you have to make.
First you have to settle on the definitions and concepts of a rest api. There are a number of great starting
points, like the excellent [rest api tutorial](http://www.restapitutorial.com/) by Todd Fredrich
and [numerous others](https://www.google.com/search?q=rest+api+tutorial).
When you have wrapped your head around the concepts of REST and decided it will give you 
[all kinds of advantages](https://www.google.nl/search?q=rest+api+advantages), now comes the time to put
it all into practice.  
  Then come all kinds of next questions, like: which language to use, which web framework, which database,
how to organize your code, how to separate data storage and business logic, how to organize code for flexibility,
how to fill in all the required and optional functionality for REST interfaces, how to implement security, how to
select a hosting provider etc etc.  
  [We](https://yourapi.io) went through all these questions ourselves also when developing a very large and ambitious
application and we had numerous discussions about all these choices and settled for a solution which is beneficial
for all other Python developers out there. We not only built a flexible framework with dynamic code execution, but 
also solved all the challenges in providing a reliable and scalable hosted solution.  
  We hope we can help you solve your tough problems by providing our Python based REST API. In this public repo
we give a walkthrough of some samples which hopefully inspire you to build your own awesome API on the yourapi platform!

## Design philosophy
We wanted to build a system where you can easily specify a rest api, using a standard method. The system itself 
consists of three layers: a web server (no assumptions on which server), the core yourapi services and data storage 
(again, no assumptions).  
  Currently, we use [Flask](http://flask.pocoo.org) as our web server. [As you can see](https://github.com/yourapi/python.rest.api/blob/master/providers/Flask/main.py), 
we put as little code in the Flask server as possible. Processing goes to our core services as quickly as possible.  
  For our database we currently use PostgreSQL, our favorite SQL database. Here we also made as little processing as 
possible, so the main services will remain unchanged when switching to a new database. In fact, we will be migrating
from Postgres to a massively scalable database (probably [Cloud spanner](https://cloud.google.com/spanner/))
in the near future.  
  For the database storage we designed a hybrid structured document/graph/SQL schema which can accommodate any 
structure and relationships without schema changes, so which is perfectly suited for the future.  
  Finally we wanted to add custom code in a structured way, so the behavior of any resource can be adapted in the 
same way. For that we chose to define **code hooks** before and after data access. These code hooks correspond to
similarly named methods in the classes which correspond to the resource names:

![Architecture overview](https://github.com/yourapi/python.rest.api/blob/master/pics/framework-diagram.svg?sanitize=true)
