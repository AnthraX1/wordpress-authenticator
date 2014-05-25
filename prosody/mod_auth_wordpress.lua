-- Prosody Wordpress Authentication
local bit = require("bit");
local md5 = require "util.hashes".md5;
local new_sasl = require "util.sasl".new;
local nodeprep = require "util.encodings".stringprep.nodeprep;
local DBI;
local connection;
local params = module:get_option("wordpress");


function encode64(input,count)
  local index_table = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  local output="";
  local i=0;
  while i< count do
    i=i+1
    local value=string.byte (string.sub(input,i,i));
    local pos=bit.band(value,0x3f);
    output =output .. string.sub(index_table,pos+1,pos+1);
    if i < count then
      value = bit.bor(value,bit.lshift(string.byte(string.sub(input,i+1,i+1)),8));
    end  
    local tmp= bit.band(bit.rshift(value,6),0x3f);
    output=output  .. string.sub(index_table,tmp+1,tmp+1);
    i=i+1;
    if i >= count then
      break;
    end  
    if i<count then
      value = bit.bor(value,bit.lshift(string.byte(string.sub(input,i+1,i+1)),16));
    end
    tmp= bit.band(bit.rshift(value,12),0x3f);
    output=output .. string.sub(index_table,tmp+1,tmp+1);
    i=i+1;
    if i >= count then
      break;
    end  
    tmp= bit.band(bit.rshift(value,18),0x3f);
    output=output .. string.sub(index_table,tmp+1,tmp+1);
  end
  return output;
end

function wp_hash(password,salt)
    local hash=md5(salt .. password);
    for i = 0, 8192, 1 do
         hash=md5(hash .. password);
    end
    local output='$P$B' .. salt .. encode64(input,16);
    return output;
end


function new_wordpress_provider(host)
  local provider = { name = "wordpress" };
  module:log("debug", "initializing wordpress authentication provider for host '%s'", host);

  function provider.test_password(username, password)
    local pass = false;
    local get_password_sql = string.format("select user_pass from `%susers` where `user_login` = ?;", params.prefix);
    local stmt = connection:prepare(get_password_sql);
    
    if stmt then
      stmt:execute(username);
      
      if stmt:rowcount() > 0 then
        local row = stmt:fetch(true);
        
        local user_pass = row.user_pass;
        local pass_salt=string.sub(user_pass,5,12);
        local md5_pass = wp_hash(password,pass_salt);
        
        pass = md5_pass == user_pass;
      end
      
      stmt:close();
    end

    if pass then
      return true;
    else
      return nil, "Auth failed. Invalid username or password.";
    end
    
  end

  function provider.get_password(username) return nil, "Password unavailable for Wordpress login."; end
  function provider.set_password(username, password) return nil, "Password unavailable for Wordpress login."; end
  function provider.create_user(username, password) return nil, "Account creation/modification not available with Wordpress login.";  end

  function provider.user_exists(username)
    module:log("debug", "Exists %s", username);
    local pass = false;
    local get_user_sql = string.format("select id from `%susers` where `user_login` = ?;", params.prefix);
    local stmt = connection:prepare(get_user_sql);
    
    if stmt then
      stmt:execute(username);
      if stmt:rowcount() > 0 then
        pass = true;
      end      
      stmt:close();
    end
    
    if not pass then
      module:log("debug", "Account not found for username '%s' at host '%s'", username, module.host);
      return nil, "Auth failed. Invalid username";
    end
    return true;
  end

  function provider.get_sasl_handler()
    local realm = module:get_option("sasl_realm") or module.host;
    
    local realm = module:get_option("sasl_realm") or module.host;
    local testpass_authentication_profile = {
      plain_test = function(sasl, username, password, realm)
        local prepped_username = nodeprep(username);
        if not prepped_username then
          module:log("debug", "NODEprep failed on username: %s", username);
          return "", nil;
        end
        return provider.test_password(prepped_username, password), true;
      end
    };
    return new_sasl(realm, testpass_authentication_profile);
    
  end
  
  return provider;
end

-- database methods from mod_storage_sql.lua
local function test_connection()
  if not connection then return nil; end
  if connection:ping() then
    return true;
  else
    module:log("debug", "Database connection closed");
    connection = nil;
  end
end

local function connect()
  if not test_connection() then
    prosody.unlock_globals();
    local dbh, err = DBI.Connect(
      "MySQL", params.database,
      params.username, params.password,
      params.host, params.port
    );
    prosody.lock_globals();
    if not dbh then
      module:log("debug", "Database connection failed: %s", tostring(err));
      return nil, err;
    end
    module:log("debug", "Successfully connected to database");
    dbh:autocommit(false); -- don't commit automatically
    connection = dbh;
    return connection;
  end
end

do -- process options to get a db connection
  local ok;
  prosody.unlock_globals();
  ok, DBI = pcall(require, "DBI");
  if not ok then
    package.loaded["DBI"] = {};
    module:log("error", "Failed to load the LuaDBI library for accessing SQL databases: %s", DBI);
    module:log("error", "More information on installing LuaDBI can be found at http://prosody.im/doc/depends#luadbi");
  end
  prosody.lock_globals();
  if not ok or not DBI.Connect then
    return; -- Halt loading of this module
  end

  params = params or {};
  
  params.host = params.host or "localhost";
  params.port = params.port or 3306;
  params.database = params.database or "wordpress";
  params.username = params.username or "NOTroot";
  params.password = params.password or "";
  params.prefix = params.prefix or "wp_";
  
  assert(connect());
end

module:add_item("auth-provider", new_wordpress_provider(module.host));

