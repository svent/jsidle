#!/usr/bin/env ruby
#
# JSidle Javascript packer 
# Author: Sven Taute
# Version: 1.0
# Web: http://github.com/svent/jsidle

require 'digest/md5'

class JSidle

	MD5_LIB = File.join(File.expand_path(File.dirname(__FILE__)), 'md5-min.js')
	MD5_FUNC = "hex_md5"
	GUESS_KEY_COUNT = 5
	# english language letter frequency
	LETTER_FREQUENCY = {
		"a" => 0.0761310205517612,
		"b" => 0.0195636854368974,
		"c" => 0.0404640533988629,
		"d" => 0.0366881926020504,
		"e" => 0.116102105435379,
		"f" => 0.0136822823265975,
		"g" => 0.028795349628028,
		"h" => 0.0221964153382716,
		"i" => 0.0876371837275477,
		"j" => 0.00187991030325584,
		"k" => 0.00871196202538414,
		"l" => 0.0537784806945616,
		"m" => 0.0274565284109197,
		"n" => 0.0694123195077586,
		"o" => 0.0613826002431693,
		"p" => 0.02824570577372,
		"q" => 0.00183072038633333,
		"r" => 0.0738116090342629,
		"s" => 0.0891364068476642,
		"t" => 0.0664694792605686,
		"u" => 0.033405300320483,
		"v" => 0.0104004593910502,
		"w" => 0.00857615508083721,
		"x" => 0.00290648248250817,
		"y" => 0.0169491344178641,
		"z" => 0.00438645737426362
	}

	attr_accessor :js
	attr_reader :opts
	attr_reader :qstring_key

	def initialize(js = "", opts = {})
		@rand_chars = ("a".."z").to_a
		@js = js
		@qstring_key = rand_string(5 + rand(10))
		@opts = {
			:delay => 2,
			:include_md5lib => true,
			:mode => :web,
			:speed => 500,
			:static => true, 
			:strip_comments => true,
		}
		update_opts(opts)
	end

	def update_opts(opts)
		@opts.each_key do |k|
			@opts[k] = opts[k] if !opts[k].nil?
		end
	end

  def <<(str)
			@js << str
	end
	def +(str)
		@js + str
	end

	def obfuscate(js)
		vars = []
		funcs = []
		func_args = []
		method_calls = []
		symbols_taken = {}

		js = strip_comments(js)
		vars = js.scan(/var\s+\b(.+?)\b/).flatten
		funcs = js.scan(/function\s+([A-Za-z0-9_]+)\(/).flatten
		func_args = js.scan(/function\s+[A-Za-z0-9_]+\(([^)]*)\)/).flatten.map { |e| e.split(/,\s*/) }.flatten
		labels = js.scan(/^\s*([A-Za-z0-9_]+):\s*$/m).flatten

		[vars, funcs, func_args, labels].flatten.sort {|a, b| b.length <=> a.length}.uniq.each do |arg|
			  symbol = rand_word(3 + rand(3)) while !symbol || symbols_taken[symbol]
				symbols_taken[symbol] = true
				js.gsub!(/\b#{arg}\b/, symbol)
		end
		
		method_calls = js.scan(/((?:[A-Za-z0-9]+\.)*[A-Za-z0-9]+)\.([a-z][A-Za-z0-9_]*)/)
		method_calls.each do |mc|
				obj, call = mc
				js.gsub!(/\b#{obj}\.#{call}\b/, "#{obj}[#{frag_str(call)}]")
		end

		return js
	end

	def pack(opts = {})
		update_opts(opts)
		js = @js
		qstring_key = @qstring_key
		server_key = rand_string(5 + rand(10))
		salt = rand_string(10 + rand(10))
		guess_keys = gen_guess_keys(@opts[:speed])
		key = qstring_key + server_key + guess_keys.join("")
		guess_keys_md5 = guess_keys.map { |e| Digest::MD5.hexdigest(salt + e) }
		key_md5 = Digest::MD5.hexdigest(key)

		js = strip_comments(js)	if @opts[:strip_comments]
		encoded = xor_encode(js, key_md5)

		encoded = encoded.unpack("H*")[0]

		eval_call = @opts[:mode] == :pdf ? "app.eval" : "window.eval"

		js_encoded = <<-ENDJS
		// prevent known ciphertext, otherwise the xor-key could easily be calculated
		var dummy = '#{rand_string(20 + rand(30))}';
		var exploit = '!!!ENCODEDEXPLOIT!!!';
		var encoded = '';
		for (i = 0;i<exploit.length;i+=2) {
			encoded += String.fromCharCode(parseInt(exploit.substring(i, i+2), 16));
		}
		var qstring_key = #{if @opts[:static] then "'#{qstring_key}'" else "location.search.substring(1)" end};
		var server_key = '#{server_key}';
		var salt = '#{salt}';
		var guess_keys_md5 = ['#{guess_keys_md5.join("','")}'];
		var partkey = qstring_key + server_key;
		var success = false;
		var key;
		var guess = ["", "", "", "", ""];
		var chars = "abcdefghijklmnopqrstuvwxyz";

		for (i = 0; i < #{GUESS_KEY_COUNT}; i++) {
		var round = 1;
		while (true) {
			guess[i] = "";
			var num = round;
			while (num > 0) {
				var mod = num % 26;
				guess[i] = chars.substring(mod, mod + 1) + guess[i];
				num = Math.floor(num / 26);
			}
			if (#{MD5_FUNC}(salt + guess[i]) == guess_keys_md5[i]) {
				break;
			}
			round++;
		}
		}
		var key = #{MD5_FUNC}(partkey + guess.join(""));
		var decoded = '';
		for (i=0;i<encoded.length;i++) {
				decoded += String.fromCharCode(encoded.charCodeAt(i) ^ key.charCodeAt(i%key.length));
		}

		#{eval_call}(decoded);
		ENDJS

		js_encoded = obfuscate(js_encoded)
		js_encoded.gsub!('!!!ENCODEDEXPLOIT!!!', encoded)
		if @opts[:include_md5lib] then
			md5code = File.open(MD5_LIB).read
			md5code = strip_comments(md5code)
			js_encoded = md5code + "\r\n" + js_encoded;
		end

		res = {}
		[:js, :js_encoded, :key, :qstring_key, :server_key, :guess_keys].each do |var|
			res[var] = eval var.to_s
		end

		return res
	end

	def obfuscate_string(str, t = 0.85)
		frag_str(str, t)
	end

protected

	def rand_string(len, chars = nil)
	chars ||= @rand_chars
	(1..len).map { |c| chars[rand(chars.length)] }.join
	end

	def rand_word(len)
		chars = @rand_chars
		str = ""
		while str.length < len do
			x = rand
			('a'..'z').inject(0) do |s,e|
				s += LETTER_FREQUENCY[e]
				if s>x then
					str << e
					break
				end
				s
			end
		end
		str
	end

	def gen_guess_keys(speed)
		chars = ("a".."z").to_a
		speed = speed * @opts[:delay]
		values = 0
		until values > 0 && values/speed.to_f > 0.7 && values/speed.to_f < 1.3
			keys = []
			values = 0
			GUESS_KEY_COUNT.times do |c|
				key = ""
				val = rand(speed * 2 / GUESS_KEY_COUNT)
				values += val
				while val > 0
					m = val % 26
					key << chars[m]
					val /= 26
				end
				keys << key.reverse
			end
		end
		keys
	end

	def frag_str(str, t = 0.85, first_call = true)
		return "'#{str}'" if t < 0.1 || str.length < 2
		pos = rand(str.length - 1) + 1
		if rand > t ** 2
			res = [ encode_str(str[0, pos]), encode_str(str[pos, str.length]) ]
		else
			res = [ frag_str(str[0, pos], t ** 2, false), frag_str(str[pos, str.length], t ** 2, false) ]
		end
		if first_call then
			return res.flatten.join(" + ")
		else
			return res
		end
	end

	def encode_str(str)
		case rand(2)
		when 0
			return "'\\x" + str.unpack("H*")[0].scan(/../).join("\\x") + "'"
		when 1
			chars = ("A".."Z").to_a + ("a".."z").to_a + ("0".."9").to_a
			unused_chars = chars - str.split(//)
			chars_to_remove = ""
			call = str.split(//).map do |c|
				chars_to_remove << rnd = rand_string(1 + rand(2), unused_chars)
				c + rnd
			end.join('')
			return "'#{call}'.replace(/[#{chars_to_remove}]/g, '')"
		end
	end

	def xor_encode(str, key)
			enc = ""
			pos = 0
			while pos < str.length
				enc << (str[pos,1].unpack("C*")[0] ^ key[pos % key.length, 1].unpack("C*")[0]).chr
				pos += 1
			end
			enc
	end

	def strip_comments(code)
		code.gsub(%r!^\s*//.*$!, '').gsub(%r!/\*.*?\*/!m, '').gsub(/(\r?\n){2,}/, "\r\n")
	end

end
