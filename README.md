# OpenAPI To Rego Code Generator

OpenAPI To Rego Code Generator allows for generation of Rego code given an [OpenAPI 3.0 Specification](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md).

## Building

Build `openapi-to-rego`  by running `make build`

## Running

The `examples` directory contains samples of OpenAPI 3.0 specification in YAML and JSON.

```bash
$ ./openapi-to-rego examples/petstore.yaml
```

This will generate the Rego code for the OAS defined in `examples/petstore.yaml`. The generated Rego code will be written to a file `policy.rego`.

To specify a different file to output the Rego code, use the `--output-filename` flag.

Default package name for the Rego policy is `httpapi.authz`. To change this use the `--package-name` flag.

Run `./openapi-to-rego --help` for more details.

## Working

### Generating Boolean Rules

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
  token.payload.scopes["write:pets"]
  token.payload.scopes["read:pets"]
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["type:apiKey"]
  token.payload.scopes["name:api_key"]
  token.payload.scopes["in:header"]
}

allow = true {
  input.path = ["pets", petId]
  input.method = "GET"
}
```

Since only one of the security requirement objects needs to be satisfied to authorize a request, there are two `allow` rules for the `post` operation object on `/pets`.

In the last `allow` rule, corresponding to the `/pets/{petId}` path object, the `petId` is a variable in the expression `input.path = ["pets", petId]` whose value will be bound to a value in the `input` that is provided to the policy.

The policy also expects a `token` to be provided in the input to verify the security requirements.


### Generating Field Filter Rules

`openapi-to-rego` leverages the [Extensions Object](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md#specification-extensions) in the OpenAPI 3.0 specification to generate Rego rules that return collections of values. An extension object named `x-security-rego-field-filter`, can be used to specify the fields that need to be filtered in the client response. 

The value for the `x-security-rego-field-filter` field is a list of objects, keyed on the `Security Scheme Name` as declared in the [Security Requirement Object](https://github.com/OAI/OpenAPI-Specification/blob/OpenAPI.next/versions/3.0.0.md#securityRequirementObject). The value for each security scheme is a list of fields that need to be filtered.

In the example below, `x-security-rego-field-filter` specifies two security schemes `petstore_auth` and `api_key`  which are declared in the `security` section. `openapi-to-rego` will use the list of scope names for these security schemes to generate the Rego policy.

Each security scheme specified in `x-security-rego-field-filter` **MUST** be declared in the `security` section for an operation.

```yaml
paths:
  /pets:
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
      x-security-rego-field-filter:
      - petstore_auth:
        - name
        - ssn
      - api_key:
        - birthdate
        - ssn
```

The generated Rego for the above OAS would look like below:

```ruby
package example
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }

filter = ["name","ssn"] {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["write:pets"]
  token.payload.scopes["read:pets"]
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["write:pets"]
  token.payload.scopes["read:pets"]
}

filter = ["birthdate","ssn"] {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["type:apiKey"]
  token.payload.scopes["name:api_key"]
  token.payload.scopes["in:header"]
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["type:apiKey"]
  token.payload.scopes["name:api_key"]
  token.payload.scopes["in:header"]
}
```

The `filter` rules specify the fields to filter in the client response. Notice that the `filter` rules contain the list of scopes corresponding to the security requirement defined for the `post` operation.

Also two `allow` rules for the `post` operation on `/pets` are created.

The policy expects a `token` to be provided in the input to verify the security requirements.

To see this example, run:

```bash
$ ./openapi-to-rego examples/petstore-rego-field-filter.yaml -p example
```

### Generating List Filter Rules

In some scenarios it may be required to filter certain objects in the response that is returned to the client. The decision about whether or not to include an object in the response may depend on certain conditions that may be specified in the OAS. These conditions could be based on the values in the object itself or in the token provided to OPA etc.

The `openapi-to-rego` uses the `x-security-rego-list-filter` extension object to specify list of objects to be filtered and the conditions that determine whether or not an object should be included in the response.

In the example below, the `x-security-rego-list-filter` field is used to determine list of objects to be filtered and their filtering conditions.

The `source` field specifies the list of objects which need to be filtered. In the OAS below, `source: list` will be translated to `input.list[x]` in the Rego policy. This means OPA expects the objects to be filtered be provided as input using the `list` key.

The `operations` field specifies the list of operations to be performed on **EACH** object in `input.list`.

The following operations are supported:

| Symbol   |      Name      |  Description |
|----------|-------------|------|
| eq |  Equality | operand_1 is equal to operand_2 |
| lt |  Less than | operand_1 is less than operand_2 |
| gte |  Greater than or equal to | operand_1 is greater than or equal to operand_2 |
| membership |  Membership | operand_2 includes operand_1 |


```yaml
paths:
  /pets:
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
      x-security-rego-list-filter:
      - source: list
        operations:
        - eq:
          - owner
          - token.payload.username
      - source: list
        operations:
        - membership:
          - owner
          - token.payload.members
        - lt:
          - age
          - 18
      - source: list
        operations:
        - membership:
          - owner
          - token.payload.members
        - gte:
          - age
          - 18
        - eq:
          - hasHouseKey
          - true
```

The generated Rego for the above OAS would look like below:

```ruby
package example
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }

list_filter[x] {
  input.list[x]
  x.owner = token.payload.username
}

list_filter[x] {
  input.list[x]
  x.owner = token.payload.members[_]
  x.age < 18
}

list_filter[x] {
  input.list[x]
  x.owner = token.payload.members[_]
  x.age >= 18
  x.hasHouseKey = true
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["write:pets"]
  token.payload.scopes["read:pets"]
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.scopes["type:apiKey"]
  token.payload.scopes["name:api_key"]
  token.payload.scopes["in:header"]
}
```
For each item in `x-security-rego-list-filter`, a corresponding `list_filter` rule is created with conditions extracted from the `operations` field specified in an `x-security-rego-list-filter` item. These conditions are then applied on each item in `input.list` which is list of objects to filter and is provided to OPA as input.

`openapi-to-rego` assumes an operand not prefixed with `token` is a field in the object being evaluated.

Also two `allow` rules for the `post` operation on `/pets` are created.

To see this example, run:

```bash
$ ./openapi-to-rego examples/petstore-rego-list-filter.yaml -p example
```

### Generating Overwrite Rules

`openapi-to-rego` defines the `x-security-rego-overwrite-filter` filter extension for scenarios where the value of a field in an object needs to be overwritten based on conditions that may be specified in the OAS. These conditions could be based on the values in the input object itself or in the token provided to OPA etc.

The `field` key in the `x-security-rego-overwrite-filter` filter extension specifies the name of a field in the input object whose value needs to be overwritten to the value specified in the `value` key of the extension based on conditions specified in the `rules` field.

The generated Rego policy returns an object with a key equal to the value of the `field` key in the extension and value equal to the `value` key of the extension or the existing value of the `field` key in the input object.

Each item in the `rules` object, specifies a new helper rule in the Rego policy while each operation specified in `operations` determines the expressions to be included in the rule body.

The following operations are supported:

| Symbol   |      Name      |  Description |
|----------|-------------|------|
| eq |  Equality | operand_1 is equal to operand_2 |
| lt |  Less than | operand_1 is less than operand_2 |
| gte |  Greater than or equal to | operand_1 is greater than or equal to operand_2 |
| membership |  Membership | operand_2 includes operand_1 |

The `negate` key controls how the results from the helper rules, apply towards asssignment of the final value for the `field` key in the result returned by OPA.

```yaml
paths:
  /pets:
    post:
      summary: Create a pet
      operationId: createPets
      tags:
        - pets
      security:
      - petstore_auth:
        - write:pets
        - read:pets
      x-security-rego-overwrite-filter:
      - field: enrolleeClaimSummaryList
        value: null
        negated: true
        rules:
        - operations:
          - eq:
            - token.payload.enrollee_type
            - '"primary"'
          - lt:
            - enrolleeAge
            - 18
        - operations:
          - eq:
            - token.payload.enrollee_idd
            - enrolleeId
          - gte:
            - age
            - 18
          - eq:
            - enrolleeSignedWaiver
            - true
      - field: enrolleeList
        value: hello
        negated: false
        rules:
        - operations:
          - eq:
            - token.payload.enrollee_type
            - '"secondary"'
          - lt:
            - enrolleeAge
            - 18
        - operations:
          - membership:
            - owner
            - token.payload.dependents
          - gte:
            - age
            - 18
          - eq:
            - enrolleeSignedWaiver
            - true
```

The generated Rego for the above OAS would look like below:

```ruby
package example
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }

response["enrolleeClaimSummaryList"] = null {
	not allow1
}

response["enrolleeClaimSummaryList"] = input.object.enrolleeClaimSummaryList {
	allow1
}

allow1 = true {
  token.payload.enrollee_type = "primary"
  input.object.enrolleeAge < 18
}

allow1 = true {
  token.payload.enrollee_idd = input.object.enrolleeId
  input.object.age >= 18
  input.object.enrolleeSignedWaiver = true
}

response["enrolleeList"] = hello {
	allow2
}

response["enrolleeList"] = input.object.enrolleeList {
	not allow2
}

allow2 = true {
  token.payload.enrollee_type = "secondary"
  input.object.enrolleeAge < 18
}

allow2 = true {
  input.object.owner = token.payload.dependents[_]
  input.object.age >= 18
  input.object.enrolleeSignedWaiver = true
}

allow = true {
  input.path = ["pets"]
  input.method = "POST"
  token.payload.claims["write:pets"]
  token.payload.claims["read:pets"]
}
```

The `response` rule returns the final value for the `field` key specified in the extension. Notice how the value for `enrolleeClaimSummaryList` is set to `null` (ie. `value` key from the extension) when `allow1` is **NOT** `true` while for `enrolleeList` it is set to `hello` (ie. `value` key from the extension) when `allow2` is `true`. This behaviour is controlled by the `negate` field in the extension.