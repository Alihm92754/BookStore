<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register (Request $request)
    {
        //basic validation of incoming data
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
            'role' => 'required|string|in:admin,user',
        ]);

        //if validation fails, return error message
        if ($validator->fails()){
            return response()->json(['error' => $validator->errors()], 422);
        }

        //create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => $request->role, //admin or user
        ]);

        //generate a token for the user
        return response()->json(['token' => $user->createToken('auth_token')->plainTextToken, 'message' => 'User registered successfully!'], 201);

    }

    public function login (Request $request)
    {
        //basic validation of incoming data
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ]);

        //if validation fails, return error message
        if ($validator->fails()){
            return response()->json(['error' => $validator->errors()], 422);
        }

        //find the user by email
        $user = User::where('email', $request->email)->first();

        //if user not found, return error message
        if (!$user || !Hash::check($request->password, $user->password)){
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        //generate a token for the user
        return response()->json(['token' => $user->createToken('auth_token')->plainTextToken, 'message' => 'User logged in successfully!'], 200);
    }

    public function logout(Request $request)
    {
        //revoke the token for the user
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'User logged out successfully!'], 200);
    }
    
}
