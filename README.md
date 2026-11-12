# Secure Web App

## Project Overview
<!-- student 1 -->

## Setup and Running the Application
<!-- student 1 -->

## Testing SQL Injection (Task 1)
<!-- student 1 -->


## Testing Authentication (Task 2)
The admin account is for testing only (admin / Admin@123) and requires running init_db.py first to create the database.

**Register:** Open /register. Enter a weak password (e.g. abc) and submit — the page returns a message listing the rules it breaks. Then enter a strong password (e.g. Strong@123) and submit — the page shows "Registered successfully".

**Login:** Go to /login and sign in with an existing account using the correct password — you are redirected to / (the home page). Then try the same username with a wrong password — the page returns "Wrong username or password".

**Logout:** While logged in, click the Logout link on the home page — you are redirected to /login.

**Back button:** After logout, press the browser Back button — you should not see the old home page; the browser re-requests /, and the session check redirects you to /login.

**Direct URL:** After logout, type / in the address bar and open it — you are redirected to /login because the session no longer contains username.

## Testing Access Control and Dashboard (Task 3)
<!-- student 3 -->


## Testing XSS and Encryption (Task 4)
<!-- student 4 -->

