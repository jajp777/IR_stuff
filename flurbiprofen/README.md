###flurbiprofen###

Drop is the docker used for scanning, build this and set the appropriate drop_tag variable in bottle.py to match. The es docker is simply elasticsearch configured with the appropriate mapping and default kibana running on top (no auth, no ssl, no nothing). 

Bottle.py is the controller, set the max_dockers variable to the number of simultaneous dockers your system can support.
