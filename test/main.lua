function floatingPragmaExample()
  local someTable = setmetatable({}, {_index = function(_, key)
    return "Default Value for ".. key
  end})

  setfenv(1, someTable)
  print(getfenv().nonExistentKey)
end

floatingPragmaExample()