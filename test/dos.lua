-- Lua code vulnerable to DDoS attack

function perform_expensive_operation()
    local sum = 0
    for i = 1, 1000000 do
        sum = sum + i
    end
    print("Sum:", sum)
end

function handle_request()
    -- Assume this function handles incoming requests
    -- It calls the expensive operation function
    perform_expensive_operation()
end

-- Main function to simulate incoming requests
function main()
    for i = 1, 10 do
        handle_request()
    end
end

main()
