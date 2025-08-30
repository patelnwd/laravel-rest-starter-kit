# Laravel 12 – Stateless REST API Starter (Sanctum **or** JWT, switchable via `.env`)

A production‑ready Laravel 12 REST API starter you can clone and reuse. It is **stateless** (Bearer tokens only), ships with **role/permission** (Spatie), **centralized JSON errors**, **rate limiting**, **Swagger (OpenAPI)**, and can authenticate via **Sanctum** *or* **JWT** based on a single `.env` flag.

> Default driver: **Sanctum**. You may switch to **JWT** later by following the JWT section.

---

## Contents
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Setup](#project-setup)
  - [1) Install Laravel](#1-install-laravel)
  - [2) Configure `.env`](#2-configure-env)
  - [3) Sanctum (default)](#3-sanctum-default)
  - [4) Optional: JWT driver](#4-optional-jwt-driver)
  - [5) Auth configuration (switchable)](#5-auth-configuration-switchable)
  - [6) Rate Limiter `throttle:api`](#6-rate-limiter-throttleapi)
  - [7) Global JSON Exception Handling](#7-global-json-exception-handling)
  - [8) Roles & Permissions (Spatie)](#8-roles--permissions-spatie)
  - [9) Example Resource (Post CRUD)](#9-example-resource-post-crud)
  - [10) API Routes (middleware in routes file)](#10-api-routes-middleware-in-routes-file)
  - [11) Swagger / OpenAPI Docs](#11-swagger--openapi-docs)
  - [12) Seed Roles & Default Admin](#12-seed-roles--default-admin)
- [Testing with cURL / HTTPie / Postman](#testing-with-curl--httpie--postman)
- [Switching Drivers: Sanctum ⇆ JWT](#switching-drivers-sanctum--jwt)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites
- PHP compatible with Laravel 12
- Composer
- MySQL/MariaDB/PostgreSQL (examples use MySQL)

---

## Quick Start
```bash
composer create-project laravel/laravel laravel-rest-starter-kit "12.*"
cd laravel-rest-starter-kit
cp .env.example .env
php artisan key:generate
# configure DB in .env, then
php artisan migrate

# Install Sanctum (default)
composer require laravel/sanctum
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan migrate

# Spatie roles/permissions
composer require spatie/laravel-permission
php artisan vendor:publish --provider="Spatie\\Permission\\PermissionServiceProvider"
php artisan migrate

# (Optional) Swagger docs
composer require darkaonline/l5-swagger
php artisan vendor:publish --provider "L5Swagger\\L5SwaggerServiceProvider"
php artisan l5-swagger:generate

# Add code changes from this README (copy/paste sections below)
# Finally seed roles & admin (after you add the seeder below):
php artisan db:seed --class=RoleSeeder

php artisan serve
```

---

## Project Setup

### 1) Install Laravel
```bash
composer create-project laravel/laravel laravel-rest-starter-kit "12.*"
cd laravel-rest-starter-kit
copy .env.example .env /Y
php artisan key:generate
```
**What this does:** creates a fresh Laravel 12 project and application key.

---

### 2) Configure `.env`
Open `.env` and set your DB + the **auth driver flag**:
```dotenv
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=api_starter
DB_USERNAME=root
DB_PASSWORD=

# Auth driver: sanctum (default) or jwt
API_AUTH_DRIVER=sanctum
```
Run the initial migrations:
```bash
php artisan migrate
```

---

### 3) Sanctum (default)
```bash
composer require laravel/sanctum
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan migrate
```
**What this does:** installs tables for personal access tokens and enables the `auth:sanctum` middleware for Bearer token auth. We will use **stateless** tokens only (no SPA/cookies and **no** `EnsureFrontendRequestsAreStateful`).

#### `app/Models/User.php` (Sanctum trait)
```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\HasApiTokens;
use Spatie\Permission\Traits\HasRoles; // added later in Spatie step

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, HasRoles; // HasRoles added in Spatie step

    protected $fillable = ['name','email','password'];
    protected $hidden = ['password','remember_token'];
}
```

> **Note:** For JWT, the User model needs extra interface methods (see the JWT section). Keep Sanctum as default until you switch.

---

### 4) Optional: JWT driver
Only needed if you want JWT now or later.
```bash
composer require tymon/jwt-auth
php artisan vendor:publish --provider="Tymon\\JWTAuth\\Providers\\LaravelServiceProvider"
php artisan jwt:secret
```
**What this does:** installs JWT package, publishes config, and generates a JWT signing key.

#### (Only for JWT) Update `app/Models/User.php`
Add the interface implementation **only if you intend to use JWT**:
```php
// Only when using JWT\ nuse Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    // ... keep traits ...

    // JWTSubject methods
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
```
> If you keep Sanctum and haven’t installed the JWT package, **do not** add the `implements JWTSubject` line, otherwise class autoloading will fail.

---

### 5) Auth configuration (switchable)
We’ll register **two guards** and choose the default at runtime from `.env`.

#### `config/auth.php`
Find the `defaults` section and set it to use `.env`:
```php
'defaults' => [
    'guard' => env('API_AUTH_DRIVER', 'sanctum'),
    'passwords' => 'users',
],
```
Add (or ensure) the guards below exist:
```php
'guards' => [
    // Sanctum token guard (for auth:sanctum)
    'sanctum' => [
        'driver' => 'sanctum',
        'provider' => 'users',
    ],

    // JWT guard (for auth:jwt)
    'jwt' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```
**What this does:** Allows routes to use `auth:` **dynamically**: `auth:".config('auth.defaults.guard')`. When `API_AUTH_DRIVER=sanctum`, it behaves like `auth:sanctum`. When `API_AUTH_DRIVER=jwt`, it behaves like `auth:jwt`.

---

### 6) Rate Limiter `throttle:api`
Define the `api` limiter so `throttle:api` works.

```bash
php artisan make:provider RouteServiceProvider
```

#### `app/Providers/RouteServiceProvider.php`
```php
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Http\Request;

class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });
    }
}
```
#### Create a api.php route file with below code `app/routes/api.php`
```php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PostController;

// Shared middlewares for all API routes
Route::middleware([
    'throttle:api',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
])->group(function () {

    // Public auth endpoints
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login',    [AuthController::class, 'login']);

    // Protected routes (driver chosen from .env: sanctum or jwt)
    Route::middleware('auth:' . config('auth.defaults.guard'))->group(function () {
        Route::get('me',     [AuthController::class, 'me']);
        Route::post('logout',[AuthController::class, 'logout']);
    });
});
```

Then clear caches:
```bash
php artisan optimize:clear
```
**What this does:** Enables `throttle:api` to rate‑limit API routes.

---

### 7) Global JSON Exception Handling
Force API routes to always return JSON for auth/validation errors (no HTML redirects; no "Route [login] not defined").

#### `bootstrap/app.php`
Add/adjust these imports at the top:
```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Validation\ValidationException;
```
Then configure exceptions:
```php
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // You can alias custom middlewares here if needed
    })
    ->withExceptions(function (Exceptions $exceptions) {
        // Treat everything under /api/* as JSON
        $exceptions->shouldRenderJsonWhen(function ($request, $e) {
            return $request->is('api/*') || $request->expectsJson();
        });

        // 401: Unauthenticated => JSON (avoids redirect to login route)
        $exceptions->render(function (AuthenticationException $e, $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'status'  => false,
                    'message' => 'Unauthenticated. Invalid or missing token.'
                ], 401);
            }
        });

        // 422: Validation errors => JSON
        $exceptions->render(function (ValidationException $e, $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'status'  => false,
                    'message' => 'Validation error',
                    'errors'  => $e->errors(),
                ], $e->status);
            }
        });
    })
    ->create();
```
**What this does:** Ensures failed auth & validation return JSON, even without `Accept: application/json` header.

---

### 8) Roles & Permissions (Spatie)
```bash
php artisan make:controller AuthController
composer require spatie/laravel-permission
php artisan vendor:publish --provider="Spatie\\Permission\\PermissionServiceProvider"
php artisan migrate
```
**What this does:** Adds tables for `roles`, `permissions`, and pivot relations. We already added `use HasRoles;` to `User` earlier.

You can protect routes with:
```php
Route::middleware(['role:admin'])
```
…or check in controllers: `$user->hasRole('admin')`, `$user->can('edit posts')` etc.

---

### 9) Example Resource (Post CRUD)
Create model, migration, controller:
```bash
php artisan make:model Post -mcr
```
#### `database/migrations/xxxx_xx_xx_xxxxxx_create_posts_table.php`
```php
Schema::create('posts', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->constrained()->onDelete('cascade');
    $table->string('title');
    $table->text('body');
    $table->timestamps();
});
```
Run migration:
```bash
php artisan migrate
```
#### `app/Models/Post.php`
```php
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    use HasFactory;

    protected $fillable = ['title','body','user_id'];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
```

#### `app/Traits/ApiResponse.php` (helper for consistent JSON)
```bash
php artisan make:trait Traits/ApiResponse
```
```php
<?php
namespace App\Traits;

trait ApiResponse
{
    protected function success($data = null, string $message = 'Success', int $code = 200)
    {
        return response()->json(['status' => true, 'message' => $message, 'data' => $data], $code);
    }

    protected function error(string $message = 'Error', int $code = 400, $errors = null)
    {
        $payload = ['status' => false, 'message' => $message];
        if ($errors) $payload['errors'] = $errors;
        return response()->json($payload, $code);
    }
}
```
```bash
php artisan make:controller PostController --resource
```
#### `app/Http/Controllers/PostController.php`
```php
<?php
namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use App\Traits\ApiResponse;

class PostController extends Controller
{
    use ApiResponse;

    public function index()
    {
        return $this->successResponse(Post::with('user')->latest()->get());
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'title' => 'required|string',
            'body'  => 'required|string',
        ]);

        $post = $request->user()->posts()->create($validated);
        return $this->successResponse($post, 'Created', 201);
    }

    public function show(Post $post)
    {
        return $this->successResponse($post->load('user'));
    }

    public function update(Request $request, Post $post)
    {
        // Optionally add policies/authorization checks here
        $post->update($request->only('title','body'));
        return $this->successResponse($post, 'Updated');
    }

    public function destroy(Post $post)
    {
        $post->delete();
        return $this->successResponse(null, 'Deleted');
    }
}
```

---

### 10) API Routes (middleware in routes file)
Laravel 12 encourages **attaching middleware in the routes**, not Kernel groups.

#### `routes/api.php`
```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PostController;

// Shared middlewares for all API routes
Route::middleware([
    'throttle:api',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
])->group(function () {

    // Public auth endpoints
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login',    [AuthController::class, 'login']);

    // Protected routes (driver chosen from .env: sanctum or jwt)
    Route::middleware('auth:' . config('auth.defaults.guard'))->group(function () {
        Route::get('me',     [AuthController::class, 'me']);
        Route::post('logout',[AuthController::class, 'logout']);

        // Anyone authenticated can read
        Route::get('posts',          [PostController::class, 'index']);
        Route::get('posts/{post}',   [PostController::class, 'show']);

        // Only admins can write (Spatie role middleware)
        Route::middleware('role:admin')->group(function () {
            Route::post('posts',        [PostController::class, 'store']);
            Route::put('posts/{post}',  [PostController::class, 'update']);
            Route::delete('posts/{post}', [PostController::class, 'destroy']);
        });
    });
});
```
**What this does:**
- `throttle:api` → rate limits
- `SubstituteBindings` → route-model binding
- `auth:<guard>` → uses Sanctum or JWT based on `.env`
- `role:admin` → role‑restricted endpoints

---

### 11) Swagger / OpenAPI Docs
```bash
composer require "darkaonline/l5-swagger"
php artisan vendor:publish --provider "L5Swagger\\L5SwaggerServiceProvider"
php artisan l5-swagger:generate
```
By default you’ll get Swagger UI at: `/api/documentation`.

Example annotations in a controller method (AuthController login):
```php
/**
 * @OA\Post(
 *   path="/api/login",
 *   tags={"Auth"},
 *   summary="User login",
 *   @OA\RequestBody(
 *     required=true,
 *     @OA\JsonContent(
 *       required={"email","password"},
 *       @OA\Property(property="email", type="string", example="test@example.com"),
 *       @OA\Property(property="password", type="string", example="secret")
 *     )
 *   ),
 *   @OA\Response(
 *     response=200,
 *     description="OK",
 *     @OA\JsonContent(
 *       @OA\Property(property="status", type="boolean", example=true),
 *       @OA\Property(property="message", type="string", example="Authenticated"),
 *       @OA\Property(property="data", type="object",
 *         @OA\Property(property="user", type="object"),
 *         @OA\Property(property="token", type="string")
 *       )
 *     )
 *   )
 * )
 */
```

---

### 12) Seed Roles & Default Admin
Create a seeder to pre‑create roles and an admin user.
```bash
php artisan make:seeder RoleSeeder
```
#### `database/seeders/RoleSeeder.php`
```php
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use Spatie\Permission\Models\Role;

class RoleSeeder extends Seeder
{
    public function run(): void
    {
        Role::firstOrCreate(['name' => 'admin']);
        Role::firstOrCreate(['name' => 'user']);

        $admin = User::firstOrCreate(
            ['email' => 'admin@example.com'],
            ['name' => 'Admin', 'password' => bcrypt('password')]
        );

        if (! $admin->hasRole('admin')) {
            $admin->assignRole('admin');
        }
    }
}
```
Run it:
```bash
php artisan db:seed --class=RoleSeeder
```

---

## AuthController (switchable tokens)
Create the controller and paste the code below.
```bash
php artisan make:controller AuthController
```

#### `app/Http/Controllers/AuthController.php`
```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Traits\ApiResponse;

class AuthController extends Controller
{
    use ApiResponse;

    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        // optional default role
        if (class_exists(\Spatie\Permission\Models\Role::class)) {
            $user->assignRole('user');
        }

        return $this->successResponse([
            'user'  => $user,
            'token' => $this->issueTokenFor($user),
        ], 'Registered', 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $driver = config('auth.defaults.guard');
        if ($driver === 'jwt') {
            if (! class_exists(\Tymon\JWTAuth\Facades\JWTAuth::class)) {
                return $this->error('JWT driver selected but package not installed. Run composer require tymon/jwt-auth', 500);
            }

            if (! $token = \Tymon\JWTAuth\Facades\JWTAuth::attempt($credentials)) {
                return $this->error('Invalid credentials', 401);
            }

            $user = auth()->user();
            return $this->successResponse(['user' => $user, 'token' => $token], 'Authenticated');
        }

        // Sanctum flow (manual check)
        $user = User::where('email', $credentials['email'])->first();
        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            return $this->error('Invalid credentials', 401);
        }

        return $this->successResponse(['user' => $user, 'token' => $this->issueTokenFor($user)], 'Authenticated');
    }

    public function me(Request $request)
    {
        return $this->successResponse($request->user());
    }

    public function logout(Request $request)
    {
        $driver = config('auth.defaults.guard');
        if ($driver === 'jwt') {
            if (class_exists(\Tymon\JWTAuth\Facades\JWTAuth::class)) {
                \Tymon\JWTAuth\Facades\JWTAuth::invalidate(\Tymon\JWTAuth\Facades\JWTAuth::getToken());
            }
        } else {
            $request->user()?->currentAccessToken()?->delete();
        }
        return $this->successResponse(null, 'Logged out');
    }

    private function issueTokenFor(User $user): string
    {
        $driver = config('auth.defaults.guard');
        if ($driver === 'jwt') {
            // "fromUser" creates a token for the given user
            return \Tymon\JWTAuth\Facades\JWTAuth::fromUser($user);
        }
        // Sanctum personal access token
        return $user->createToken('api-token')->plainTextToken;
    }
}
```

---

## Testing with cURL / HTTPie / Postman
**Important header:** API responds JSON automatically, but including it is good practice.

Register:
```bash
curl -X POST http://127.0.0.1:8000/api/register \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"t@example.com","password":"secret"}'
```
Login:
```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"email":"t@example.com","password":"secret"}'
```
Use token:
```bash
curl http://127.0.0.1:8000/api/me \
  -H "Accept: application/json" \
  -H "Authorization: Bearer <PASTE_TOKEN_HERE>"
```

---

## Switching Drivers: Sanctum ⇆ JWT
1. Set `.env`:
   ```dotenv
   API_AUTH_DRIVER=sanctum   # or jwt
   ```
2. If switching **to JWT**:
   - Install JWT package and run `jwt:secret` (see step 4)
   - Update `User` to implement `JWTSubject` (see step 4)
3. Clear caches:
   ```bash
   php artisan optimize:clear
   ```
4. Your protected routes already use `auth:".config('auth.defaults.guard')`, no changes required.

---

## Troubleshooting
- **`Route [login] not defined` on bad token** → Ensure the `bootstrap/app.php` exception handlers are added (Step 7). Also include `Accept: application/json` in requests.
- **`Rate limiter [api] is not defined`** → Add the `RateLimiter::for('api', ...)` in `RouteServiceProvider` (Step 6) and run `php artisan optimize:clear`.
- **Routes not showing in `route:list`** → Ensure `bootstrap/app.php` has `->withRouting(api: __DIR__.'/../routes/api.php', ...)`.
- **JWT selected but package missing** → Install `tymon/jwt-auth` and add `JWTSubject` to `User`.
- **Using Postman** → Always set `Authorization: Bearer <token>` and preferably `Accept: application/json`.

---

**You’re done!** Zip this folder to reuse as a boilerplate. Change the name, swap the driver in `.env`, and ship 🚀

