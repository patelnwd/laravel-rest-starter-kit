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
