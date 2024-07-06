function floatingPragmaExample()
  -- This will behave differently in Lua versions before 5.2
  local someTable = setmetatable({}, {_index = function(_, key)
    return "Default Value for ".. key
  end})

  -- Using deprecated functions
  setfenv(1, someTable)
  print(getfenv().nonExistentKey)
end

floatingPragmaExample()