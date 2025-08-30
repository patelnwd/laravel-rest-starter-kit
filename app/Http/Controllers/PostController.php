<?php
namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use App\Traits\ApiResponse;
use Illuminate\Http\Response;

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

        $validated['user_id'] = $request->user()->id;
        $post = (new Post())->create($validated);
        return $this->response($post, Response::HTTP_CREATED);
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
