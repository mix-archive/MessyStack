async function main() {
  const result = await fetch('http://127.0.0.1:8787/cf', { signal: AbortSignal.timeout(3 * 1000) }).then((res) => {
    if (!res.ok) {
      throw new Error('Server is not healthy');
    }
    return res.json();
  });
  console.log(result);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
