# OpenAPI To Rego Code Generator

OpenAPI To Rego Code Generator allows for generation of Rego code given an [OpenAPI 3.0 Specification](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md).

## Building

Build `openapi-to-rego`  by running `make build`

## Running

The `examples` directory contains samples of OpenAPI 3.0 specification in YAML and JSON.

```bash
$ ./openapi-to-rego examples/petstore.yaml
```

This will generate the Rego code for the OAS defined in `examples/petstore.yaml`. The generated Rego code will be wrtitten to a file `policy.rego`. 

To specify a different file to output the Rego code, use the `--output-filename` flag.

Default package name for the Rego policy is `httpapi.authz`. To change this use the `--package-name` flag.

Run `./openapi-to-rego --help` for more details.

## Working

`openapi-to-rego` looks at the [Paths Object](https://github.com/OAI/OpenAPI-Specification/blob/OpenAPI.next/versions/3.0.0.md#paths-object), [Operation Object](https://github.com/OAI/OpenAPI-Specification/blob/OpenAPI.next/versions/3.0.0.md#operationObject) and [Security Requirement Object](https://github.com/OAI/OpenAPI-Specification/blob/OpenAPI.next/versions/3.0.0.md#securityRequirementObject) in the OpenAPI 3.0 specification file to generate the Rego policy.

The example below has two path objects namely `/pets` and `/pets/{petId}`. `/pets` has two operation objects `get` and `post` while `/pets/{petId}` has `get`. 

Additionally the `post` operation object on `/pets` has two security requirement objects `petstore_auth` and `api_key`.

```yaml
paths:
  /pets:
    get:
      summary: List all pets
      operationId: listPets
      tags:
        - pets
      parameters:
        - name: limit
          in: query
          description: How many items to return at one time (max 100)
          required: false
          schema:
            type: integer
            format: int32
    post:
      summary: Create a pet
      operationId: createPets
      tags:
        - pets
      security:
      - petstore_auth:
        - write:pets
        - read:pets
      - api_key:
        - type:apiKey
        - name:api_key
        - in:header
  /pets/{petId}:
    get:
      summary: Info for a specific pet
      operationId: showPetById
      tags:
        - pets
```

The generated Rego for the above OAS would look like below:

```rego
package httpapi.authz
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }

allow = true {
  input.path = ["pets"]
  input.method = "GET"
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.claims["write:pets"]
  token.payload.claims["read:pets"]
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.claims["type:apiKey"]
  token.payload.claims["name:api_key"]
  token.payload.claims["in:header"]
}

allow = true {
  input.path = ["pets", petId]
  input.method = "GET"
}
```

Since only one of the security requirement objects needs to be satisfied to authorize a request, there are two `allow` rules for the `post` operation object on `/pets`.

In the last `allow` rule, corresponding to the `/pets/{petId}` path object, the `petId` is a variable in the expression `input.path = ["pets", petId]` whose value will be bound to a value provided to the policy as `input`.

The policy also expects a `token` to be provided in the input to verify the security requirements.
