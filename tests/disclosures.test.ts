import * as sd from '../src/selective-disclosure';

test("disclosure encoding", async () => {
    const example = ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"];
    const expectedDisclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd";
    const actualDisclosure = sd.encodeDisclosure(example);
    expect(actualDisclosure).toBe(expectedDisclosure);
});

test("disclosure hashing", async () => {
    const d = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    const expectedDigest = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY";
    const actualDigest = sd.hashDisclosure("sha256", d);
    expect(actualDigest).toBe(expectedDigest);

});
