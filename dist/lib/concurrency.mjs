export async function mapBounded(values, limit, worker) {
    const output = new Array(values.length);
    let cursor = 0;
    async function run() {
        while (true) {
            const index = cursor++;
            if (index >= values.length)
                return;
            output[index] = await worker(values[index], index);
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => run()));
    return output;
}
