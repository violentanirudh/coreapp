<?php

class HomeController {

	public static function home() {
		
		CoreApp::render('home');

		echo "<pre>";
		print_r(json_decode(CoreApp::fetch('GET', 'https://catfact.ninja/fact'), true));

		return true;

	}

	public static function blog($slug) {
		
		$content = ['slug' => $slug];

		CoreApp::render('blog', $content);

		return true;

	}

	public static function notfound($pattern) {

		CoreApp::render('404');

	}

	public static function request() {

		echo '<pre>';
		print_r(CoreApp::authenticate());
		echo '</pre>';

	}

	public static function share() {
		CoreApp::render('file');
		return true;
	}

	public static function file() {

		$file = CoreApp::request()['files']['file']; 

		print_r(CoreApp::upload($file, 'anirudhsingh.pdf', './', 10*1024, ['pdf']));

	}

	public static function register() {
		
		echo CoreApp::login(['email' => 'anirudh@example.com', 'password' => 'something']);

	}

	public static function session($id) {

		$something = CoreApp::flash('DISPLAY', 'id');
		
		if ($something) {
			echo $something;
		}

		CoreApp::flash('SET', 'id', $id);

	}

	public static function verify($token) {

		echo (CoreApp::userVerify($token)) ? 'true' : 'false';

	}	

}
