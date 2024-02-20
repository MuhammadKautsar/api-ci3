<?php
defined('BASEPATH') OR exit('No direct script access allowed');

require_once APPPATH .'/libraries/JWT.php';
use \Firebase\JWT\JWT;
require_once APPPATH .'/libraries/Key.php';
use Firebase\JWT\Key;

class UserController extends CI_Controller {

	private $secret = 'this is key secret';

	public function __construct()
	{
		parent::__construct();
		$this->load->model('user');

		//=== ALLOWING CORS
		header('Access-Control-Allow-Origin: *');
		header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
		header('Access-Control-Allow-Headers: Content-Type, Content-Range, Content-Disposition, Content-Description');
	}

	public function response($data, $status = 200)
	{
		$this->output
			->set_content_type('application/json')
			->set_status_header($status)
			->set_output(json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))
			->_display();

		exit;
	}

	public function register()
	{
		return $this->response($this->user->save());
	}

	public function get_all()
	{
		return $this->response($this->user->get());
	}

	public function get($id)
	{
		return $this->response($this->user->get('id', $id));
	}

	public function login()
	{
		if (!$this->user->is_valid()) {
			return $this->response([
				'success' => false,
				'message' => 'email atau password salah'
			]);
		}

		$user = $this->user->get('email', $this->input->post('email'));

		$payload['id'] = $user->id;
		// $payload['email'] = $user->email;

		$date = new DateTime(); // Buat objek DateTime
		$timestamp = strtotime($date->format('Y-m-d H:i:s')); // Konversi ke timestamp

		$payload['iat'] = $timestamp;
		$payload['exp'] = $timestamp + 60*60*2; // Tambahkan 2 jam (7200 detik)

		$output['id_token'] = JWT::encode($payload, $this->secret, 'HS256');
		$this->response($output);
	}

	public function check_token()
	{
		$jwt = $this->input->get_request_header('Authorization');

		try {
			$decoded = JWT::decode($jwt, new Key($this->secret, 'HS256'));
			return $decoded->id;
			// var_dump($decoded);
		} catch(\Exception $e) {
			return $this->response([
				'success' => false,
				'message' => 'gagal, error token'
			], 401);
		}
	}

	public function delete($id)
	{
		if ($this->protected_method($id)) {
			return $this->response($this->user->delete($id));
		}		
	}

	public function update($id)
	{
		$data = $this->get_input();
		if ($this->protected_method($id)) {
			return $this->response($this->user->update($id, $data));
		}
	}

	public function get_input()
	{
		return json_decode(file_get_contents('php://input'));
	}

	public function protected_method($id)
	{
		if ($id_from_token = $this->check_token()) {
			if ($id_from_token == $id) {
				return true;
			} else {
				return $this->response([
					'success' => false,
					'message' => 'user yang login berbeda'
				], 403);
			}
		}
	}
}
