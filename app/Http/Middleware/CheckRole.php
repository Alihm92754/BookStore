<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, ...$roles): Response
    {
        //check if the user is authenticated and has the required role
        if (!in_array($request->user()->role, $roles)) {
            return response()->json(['error' => 'Unauthorized'], 403); // forbidden
        }

        //if the user is authenticated and has the required role, proceed with the request
        return $next($request); // BookController CRUD
    }
}
