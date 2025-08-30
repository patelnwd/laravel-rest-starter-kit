<?php
namespace App\Traits;

use Symfony\Component\HttpKernel\Exception\HttpException;

trait ApiResponse
{
    protected function successResponse($data = null, string $message = 'Success', int $code = 200)
    {
        return response()->json(['status' => true, 'message' => $message, 'data' => $data], $code);
    }

    protected function errorResponse(string $message = 'Error', int $code = 400, $errors = null)
    {
        $payload = ['status' => false, 'message' => $message];
        if ($errors) $payload['errors'] = $errors;
        return response()->json($payload, $code);
    }

    protected function response(string $message, int $code, mixed $details=null){
        return response()->json([
            'status'=> $code >=200 && $code < 300,
            'message'=> $message,
            'details'=> $details
        ], $code);
    }
}
