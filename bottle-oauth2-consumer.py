"""
A suite of helper methods to manage authenticating via Oauth2 and a 
convenience method for annotating methods that require some kind of 
authorization
"""

"""
Copyright (c) 2013 Gunnar Gissel <ggissel@alumni.cmu.edu>

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the 
"Software"), to deal in the Software without restriction, including 
without limitation the rights to use, copy, modify, merge, publish, 
distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so, subject to 
the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import functools
import urllib.request as ur
import urllib.parse as up
import json

__author__ = 'Gunnar Gissel <ggissel@alumni.cmu.edu>'
__version__ = '0.3'



def auth_required(onFail, isAuthorized, **kwargs):
	"""
	Annotation processor for methods that require authorization
	
	Keyword arguments:
	
	onFail -- a function that is called if the isAuthorized function 
    returns	False
	isAuthorized -- a function that returns True if the user is 
    authorized for what they are requesting and False, otherwise
	"""
	def _auth_required(old_function, *args, **kwargs):
		def _new_function(*args, **kwargs):
			if isAuthorized():
				return old_function(*args, **kwargs)
			else:
				onFail()
		return functools.wraps(old_function)(_new_function)
	return _auth_required


def generate_auth_url(	redirect_uri, 
						client_id, 
						scope, 
						response_type="code", 
						url=("https://accounts.google.com"
                             "/o/oauth2/auth")):
	"""
	Generates the initial oauth2 url.

	Keyword arguments:
	redirect_uri -- the uri this Oauth2 request should redirect to
	client_id -- your Oauth2 client Id
	scope -- a tuple of the scopes of authorization you are requestion
	response_type -- the type of response desired
	url -- the url to make the request of
	
	Returns a string that should be a valid Oauth2 url

	"""	

	catted_scope = ""
	for s in scope:
        #makes an html string out of scope strings, joins with %20
		catted_scope += "%20" + s 
	catted_scope = catted_scope[3:] #removes the initial space
	return url +('?response_type={response_type}&redirect_uri='
                 '{redirect_uri}&client_id={client_id}'
			     '&scope={scope}').format(response_type=response_type,
									      redirect_uri=redirect_uri,
									      client_id=client_id,
									      scope=catted_scope)
								 
def get_access_token(	client_id, 
                        client_secret, 
                        redirect_uri, 
                        auth_url, 
                        code,
                        onFail,
                        grant_type='authorization_code'):
    """
    Gets an access token from the url created by generate_auth_url.  The
    access_token is assumed to be a json string, but we don't assume 
    that the actual token we care about is mapped to 'access_token', so 
    we don't try to parse it out.  

    Keyword arguments:
    client_id -- your Oauth2 client Id
    client_secret -- your Oauth2 client secret
    redirect_uri -- the uri this Oauth2 request should redirect to
    auth_url -- the url you are asking for Oauth2 authorization from
    code -- the authentication code returned from your initial Oauth2 
    request
    onFail -- a method that will be called if an exception opening the 
    auth_url is	encountered
    grant_type -- the type of grant you are requesting

    Returns a dict
    """

    mydata = up.urlencode({ 'code':code,
                            'redirect_uri':redirect_uri,
                            'client_id':client_id,
                            'client_secret':client_secret,
                            'grant_type':'authorization_code'
                            })
    mydata = mydata.encode('utf-8') #python3 encoding issues
    print(auth_url)
    auth_req = ur.Request(	auth_url,
                            headers={'content-type':
                                     'application/x-www-form-urlencoded'
                                    })
    try:
        print(auth_req, mydata)
        auth_page = ur.urlopen(auth_req, data = mydata)
    except:
        onFail()
    #python3 encoding issues
    content = auth_page.readall().decode('utf-8') 
    token_data = json.loads(content)
    return token_data
	
def get_authorized_data(data_uri, access_token, onFail):
	"""
	Gets data from exposed apis requested in generate_auth_url's scope
	using the access token from get_access_token
	
	Keyword arguments:
	data_uri -- the uri to request authorized data from
	access_token -- the access token to be given to the data_uri
	onFail -- a function that is called if an exception is enountered 
	opening the data_uri

	Returns a dict with whatever authorized info was returned
	"""

	uri = data_uri + '?access_token=' + access_token
	print(uri)
	try:		
		data_page = ur.urlopen(uri)
	except Exception as e:
		onFail()
	content = data_page.readall().decode('utf-8')
	return json.loads(content)
