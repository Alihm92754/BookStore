<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Book;
use Illuminate\Http\Request;

class BookController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return Book::all();
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $book = Book::create($request->all()); //create new book
        return response()->json($book, 201); //return the book and 201 status code
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        $book = Book::find($id); //find the book by id
        if(!$book) {
            return response()->json(['message' => 'Book not found'], 404); //return 404 error if book not found
        }

        return $book; //return the book
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        $book = Book::find($id); //find the book
        if(!$book) {
            return response()->json(['message' => 'Book not found'], 404); //return 404 error if book not found
        }

        $book->update($request->all()); //update the book
        return response()->json($book, 200); //return the book and 200 status code
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        $book = Book::find($id); //find the book by id
        if(!$book) {
            return response()->json(['message' => 'Book not found'], 404); //return 404 error if book not found
        }

        $book->delete(); //delete the book
        return response()->json(['message' => 'Book deleted'], 200); //delete the book and 200 status code
    }
}
