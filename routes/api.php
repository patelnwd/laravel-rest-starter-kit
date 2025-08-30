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
