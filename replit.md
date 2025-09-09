# Overview

This is a Chase Rice fanpage web application that serves as an official fan community platform. The application combines a public-facing website with raffle functionality, allowing fans to enter contests for virtual meet-and-greet opportunities with the country music artist. The system includes both member registration capabilities and administrative tools for managing raffles and selecting winners.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The application uses a traditional server-side rendered architecture with Flask templating. The frontend employs:
- **Jinja2 templates** with a base template system for consistent layout and navigation
- **Tailwind CSS via CDN** for styling, supplemented by custom CSS variables for brand colors
- **Font Awesome icons** and Google Fonts for enhanced visual design
- **AOS (Animate On Scroll)** library for smooth page animations
- **Responsive grid layouts** for optimal display across devices

## Backend Architecture
The backend is built with **Flask**, a lightweight Python web framework, following these patterns:
- **Route-based URL handling** for different pages (home, music, tour, raffle, admin)
- **Session management** for user authentication (both members and admin)
- **Form handling** with POST/GET request processing
- **Password hashing** using Werkzeug's security utilities for secure user credentials
- **Database abstraction** through raw SQLite queries with proper connection management

## Data Storage Solutions
The application uses **SQLite** as the primary database with the following schema design:
- **raffle_entries table** - stores fan raffle submissions with name, email, favorite song, and timestamp
- **admin_users table** - manages administrative access with hashed passwords
- **members table** - handles fan registration with user profiles (username, email, first_name, last_name), credentials, and registration timestamp
- **winners table** - tracks selected raffle winners with foreign key relationships

The database initialization occurs on application startup with automatic table creation and default admin user seeding.

## Authentication and Authorization
The system implements a comprehensive two-tier authentication model:
- **Member authentication** - allows fans to register with username/email, login, and access member-exclusive content (Bio, Music, Tour, Raffles, Winners tabs)
- **Admin authentication** - provides administrative access to raffle management, winner selection, and dashboard analytics
- **Session-based security** using Flask's session management with configurable secret keys
- **Password security** through hashing and validation to protect user credentials
- **Protected routes** with authentication decorators that redirect non-logged-in users to the login page

## Page Structure and Routing
The application follows a multi-page structure with dedicated routes:
- **Public pages** - home page accessible to all visitors
- **Protected member pages** - bio, music, tour, raffle, winners (requires member authentication)
- **Member authentication pages** - registration (/register), login (/login), logout (/logout)
- **Administrative interface** - dashboard, winner selection, raffle management
- **Dynamic navigation** showing login/register options for guests, and member tabs plus logout for authenticated users
- **Template inheritance** ensures consistent branding and navigation across all pages

# External Dependencies

## Python Libraries
- **Flask 2.3.3** - core web framework for routing, templating, and request handling
- **Werkzeug 2.3.7** - WSGI utilities and security functions for password hashing

## Frontend CDN Resources
- **Tailwind CSS** - utility-first CSS framework loaded via CDN for rapid styling
- **Font Awesome 6.4.0** - icon library for enhanced user interface elements
- **Google Fonts** - Montserrat and Open Sans font families for typography
- **AOS (Animate On Scroll)** - animation library for smooth page transitions

## Database
- **SQLite** - embedded database solution requiring no external database server setup
- Built-in Python sqlite3 module for database operations and connection management

## Environment Configuration
- **Environment variables** support for SECRET_KEY configuration
- Fallback defaults for development environments when environment variables are not set