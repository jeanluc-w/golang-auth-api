# SQL to run on your machine when setting up a test DB

CREATE ROLE edibubble_admin LOGIN PASSWORD '*set_local_password_string_here*';
CREATE DATABASE edibubble WITH OWNER = edibubble_admin;