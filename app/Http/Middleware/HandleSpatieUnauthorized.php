<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Spatie\Permission\Exceptions\UnauthorizedException;
use Symfony\Component\HttpFoundation\Response;

class HandleSpatieUnauthorized
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
       try {
            return $next($request);
        } catch (UnauthorizedException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Forbidden',
                'details' => 'You do not have the required role/permission.',
            ], Response::HTTP_FORBIDDEN);
        }
    }
}
